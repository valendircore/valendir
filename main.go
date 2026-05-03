package main

/*
Valendir Core v3 — single-file production artifact.

What this service does:
  - Runs a single-node durable authorization/clearance engine backed by bbolt.
  - Models clearances as an explicit finite-state machine.
  - Tracks mandate spend commitments atomically so one mandate cannot be overspent.
  - Accepts Ed25519-signed agent actions for accept/release/dispute.
  - Issues Ed25519-signed attestations over canonical attestation bytes.
  - Maintains synchronous per-clearance tamper-evident audit chains.
  - Appends durable business events and fans them out through a durable webhook outbox.
  - Uses per-webhook queued deliveries, bounded workers, queue-based retry, and HMAC signatures.
  - Provides idempotent mutation handling scoped by caller subject + route + request hash.
  - Uses cursor pagination everywhere; no unbounded list endpoints.

Internal architecture, kept in one file for artifact portability:

    HTTP -> Service -> FSM -> BoltStore -> EventLog -> Outbox -> Webhook Workers

Production note:
  This file is deployable as-is, but the natural repo split is cmd/, internal/domain,
  internal/fsm, internal/service, internal/store/bolt, internal/api, internal/webhook,
  internal/crypto, and internal/idempotency.
*/

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	StatePending          State = "PENDING"
	StateAgentsIdentified State = "AGENTS_IDENTIFIED"
	StateMandateVerified  State = "MANDATE_VERIFIED"
	StateProofSubmitted   State = "PROOF_SUBMITTED"
	StateProofVerified    State = "PROOF_VERIFIED"
	StateAccepted         State = "ACCEPTED"
	StateReleased         State = "RELEASED"
	StateDisputed         State = "DISPUTED"
	StateResolved         State = "RESOLVED"
	StateExpired          State = "EXPIRED"

	EvtClearanceCreated = "valendir.clearance.created.v3"
	EvtAgentsIdentified = "valendir.clearance.agents_identified.v3"
	EvtMandateVerified  = "valendir.clearance.mandate_verified.v3"
	EvtProofSubmitted   = "valendir.proof.submitted.v3"
	EvtProofVerified    = "valendir.proof.verified.v3"
	EvtAccepted         = "valendir.clearance.accepted.v3"
	EvtReleased         = "valendir.authorization.released.v3"
	EvtDisputed         = "valendir.clearance.disputed.v3"
	EvtResolved         = "valendir.clearance.resolved.v3"
	EvtExpired          = "valendir.clearance.expired.v3"
	EvtAdminReleased    = "valendir.authorization.admin_released.v3"

	maxBody                         = 1 << 20
	maxArtifactsPerProof            = 32
	maxWebhookAttempts              = 10
	maxNonceEntries                 = 200_000
	maxIdempotencyEntries           = 200_000
	idempotencyTTL                  = 24 * time.Hour
	signatureSkewSeconds            = 10 * 60
	nonceTTL                        = 15 * time.Minute
	defaultClearanceTTLDays         = 7
	defaultWebhookDoneRetentionDays = 7
	timeKeyLayout                   = "2006-01-02T15:04:05.000000000Z"
	maxShortString                  = 256
	maxLongString                   = 4096
	maxURIString                    = 2048
	maxIntentConstraints            = 32
	maxIdempotencyResponseBody      = 256 << 10
	minAdminTokenLength             = 32
)

var (
	bMeta               = []byte("meta")
	bOrgs               = []byte("orgs")
	bAgents             = []byte("agents")
	bAgentsByOrg        = []byte("agents_by_org")
	bMandates           = []byte("mandates")
	bMandatesByAgent    = []byte("mandates_by_agent")
	bMandateCommitted   = []byte("mandate_committed")
	bClearances         = []byte("clearances")
	bClearByCreated     = []byte("clearances_by_created")
	bClearByState       = []byte("clearances_by_state")
	bClearByExpiry      = []byte("clearances_by_expiry")
	bClearByMandateAct  = []byte("clearances_by_mandate_active")
	bProofs             = []byte("proofs")
	bProofsByClearance  = []byte("proofs_by_clearance")
	bWebhooks           = []byte("webhooks")
	bWebhooksByOrg      = []byte("webhooks_by_org")
	bWebhooksByOrgEvent = []byte("webhooks_by_org_event")
	bEvents             = []byte("events")
	bEventsByClearance  = []byte("events_by_clearance")
	bAuditByClearance   = []byte("audit_by_clearance")
	bDeliveries         = []byte("webhook_deliveries")
	bDeliveryDue        = []byte("webhook_due")
	bDeliveryDead       = []byte("webhook_dead")
	bDeliveryDone       = []byte("webhook_done")
	bNonces             = []byte("nonces")
	bIdempotency        = []byte("idempotency")
	bIdempotencyByTime  = []byte("idempotency_by_time")

	allBuckets = [][]byte{
		bMeta, bOrgs, bAgents, bAgentsByOrg, bMandates, bMandatesByAgent, bMandateCommitted,
		bClearances, bClearByCreated, bClearByState, bClearByExpiry, bClearByMandateAct,
		bProofs, bProofsByClearance, bWebhooks, bWebhooksByOrg, bWebhooksByOrgEvent,
		bEvents, bEventsByClearance, bAuditByClearance, bDeliveries, bDeliveryDue,
		bDeliveryDead, bDeliveryDone, bNonces, bIdempotency, bIdempotencyByTime,
	}

	validArtifactTypes = map[string]bool{
		"quote": true, "invoice": true, "receipt": true, "sla": true, "delivery_note": true,
		"inspection": true, "photo": true, "contract": true, "risk_screen": true,
		"support_note": true, "approval": true, "other": true,
	}
	allowedArtifactSchemes = map[string]bool{"https": true, "ipfs": true}

	validIntentDomains = map[string]bool{
		"commercial_agent": true,
		"inference_rack":   true,
		"telecom_network":  true,
		"datacenter_ops":   true,
	}
	validRiskClasses = map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}
	validConstraintKinds = map[string]bool{
		"policy":       true,
		"power":        true,
		"thermal":      true,
		"sla":          true,
		"commercial":   true,
		"data":         true,
		"jurisdiction": true,
		"safety":       true,
	}
)

// ---------- domain ----------

type State string

type Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type Agent struct {
	ID           string   `json:"id"`
	OrgID        string   `json:"org_id"`
	OrgName      string   `json:"org_name"`
	Role         string   `json:"role"`
	Scope        []string `json:"scope,omitempty"`
	PublicKeyB64 string   `json:"public_key_b64"`
	Status       string   `json:"status"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type Mandate struct {
	ID              string   `json:"id"`
	AgentID         string   `json:"agent_id"`
	OrgID           string   `json:"org_id"`
	OrgName         string   `json:"org_name"`
	AgentRole       string   `json:"agent_role"`
	ValueLimitCents int64    `json:"value_limit_cents"`
	AllowedActions  []string `json:"allowed_actions"`
	Jurisdiction    string   `json:"jurisdiction"`
	Policy          string   `json:"policy"`
	ExpiresAt       string   `json:"expires_at"`
	Active          bool     `json:"active"`
	CreatedAt       string   `json:"created_at"`
}

type StateEvent struct {
	State     State  `json:"state"`
	Timestamp string `json:"timestamp"`
}

type Artifact struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	SHA256 string `json:"sha256"`
	URI    string `json:"uri,omitempty"`
}

type IntentConstraint struct {
	Name           string `json:"name"`
	Kind           string `json:"kind,omitempty"` // policy, power, thermal, sla, commercial, data, jurisdiction, safety
	Operator       string `json:"operator,omitempty"`
	Value          string `json:"value,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

type ProofBundle struct {
	ID          string     `json:"id"`
	ClearanceID string     `json:"clearance_id"`
	SubmittedBy string     `json:"submitted_by"`
	Role        string     `json:"role"`
	Artifacts   []Artifact `json:"artifacts"`
	SealHash    string     `json:"seal_hash"`
	CreatedAt   string     `json:"created_at"`
}

type Dispute struct {
	ID         string `json:"id"`
	OpenedBy   string `json:"opened_by"`
	Reason     string `json:"reason"`
	Status     string `json:"status"`
	PacketHash string `json:"packet_hash"`
	CreatedAt  string `json:"created_at"`
	ResolvedAt string `json:"resolved_at,omitempty"`
}

type ReleaseEvent struct {
	ID           string   `json:"id"`
	ClearanceID  string   `json:"clearance_id"`
	WebhookEvent string   `json:"webhook_event"`
	AcceptedBy   string   `json:"accepted_by"`
	ReleasedBy   string   `json:"released_by"`
	ValueCents   int64    `json:"value_cents"`
	ProofState   string   `json:"proof_state"`
	ProofSeals   []string `json:"proof_seals"`
	ReleasedAt   string   `json:"released_at"`
}

type Clearance struct {
	ID              string             `json:"id"`
	BuyerAgentID    string             `json:"buyer_agent_id"`
	SellerAgentID   string             `json:"seller_agent_id"`
	MandateID       string             `json:"mandate_id,omitempty"`
	TransactionType string             `json:"transaction_type"`
	Label           string             `json:"label"`
	IntentDomain    string             `json:"intent_domain,omitempty"`    // commercial_agent, inference_rack, telecom_network, datacenter_ops
	IntentSummary   string             `json:"intent_summary,omitempty"`   // human-readable requested outcome
	SystemOfRecord  string             `json:"system_of_record,omitempty"` // ERP, scheduler, DCIM, OSS/BSS, payment rail, etc.
	RiskClass       string             `json:"risk_class,omitempty"`       // low, medium, high, critical
	Constraints     []IntentConstraint `json:"constraints,omitempty"`      // machine-checkable clearance constraints
	RollbackURI     string             `json:"rollback_uri,omitempty"`     // reference to rollback plan held outside Valendir
	RollbackHash    string             `json:"rollback_hash,omitempty"`    // sha256 of rollback artifact
	ValueCents      int64              `json:"value_cents"`
	TTLSeconds      int                `json:"ttl_seconds"`
	ExpiresAt       string             `json:"expires_at"`
	State           State              `json:"state"`
	History         []StateEvent       `json:"history"`
	ProofBundleIDs  []string           `json:"proof_bundle_ids,omitempty"`
	AcceptedBy      string             `json:"accepted_by,omitempty"`
	ReleaseEvent    *ReleaseEvent      `json:"release_event,omitempty"`
	Dispute         *Dispute           `json:"dispute,omitempty"`
	CreatedAt       string             `json:"created_at"`
	UpdatedAt       string             `json:"updated_at"`
}

type WebhookEndpoint struct {
	ID        string   `json:"id"`
	OrgID     string   `json:"org_id"`
	URL       string   `json:"url"`
	Secret    string   `json:"secret,omitempty"`
	Events    []string `json:"events,omitempty"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
}

type Event struct {
	ID          string          `json:"id"`
	Seq         uint64          `json:"seq"`
	Type        string          `json:"type"`
	ClearanceID string          `json:"clearance_id,omitempty"`
	ActorID     string          `json:"actor_id,omitempty"`
	OrgIDs      []string        `json:"org_ids,omitempty"`
	Payload     json.RawMessage `json:"payload"`
	CreatedAt   string          `json:"created_at"`
}

type ClearanceAuditEntry struct {
	ClearanceID string `json:"clearance_id"`
	LocalSeq    uint64 `json:"local_seq"`
	Timestamp   string `json:"timestamp"`
	RequestID   string `json:"request_id,omitempty"`
	ActorID     string `json:"actor_id,omitempty"`
	Action      string `json:"action"`
	PayloadHash string `json:"payload_hash"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
}

type WebhookDelivery struct {
	ID          string          `json:"id"`
	EventID     string          `json:"event_id"`
	Event       string          `json:"event"`
	ClearanceID string          `json:"clearance_id,omitempty"`
	WebhookID   string          `json:"webhook_id"`
	OrgID       string          `json:"org_id"`
	URL         string          `json:"url"`
	Body        json.RawMessage `json:"body,omitempty"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	InFlight    bool            `json:"in_flight"`
	LastError   string          `json:"last_error,omitempty"`
	NextAttempt string          `json:"next_attempt,omitempty"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

type Attestation struct {
	Schema       string   `json:"schema"`
	AuthorityID  string   `json:"authority_id"`
	ClearanceID  string   `json:"clearance_id"`
	Decision     string   `json:"decision"`
	State        State    `json:"state"`
	ValueCents   int64    `json:"value_cents"`
	ReasonCodes  []string `json:"reason_codes"`
	PacketRoot   string   `json:"packet_root"`
	SignatureB64 string   `json:"signature_b64"`
	IssuedAt     string   `json:"issued_at"`
}

type Page[T any] struct {
	Items      []T    `json:"items"`
	Count      int    `json:"count"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type PageQuery struct {
	Limit  int
	Cursor string
}

type Config struct {
	Addr                     string
	DBPath                   string
	ReadToken                string
	WriteToken               string
	EmergencyToken           string
	CORS                     string
	TTLDays                  int
	MaxDBSizeBytes           int64
	WebhookDoneRetentionDays int
	DevMode                  bool
}

type signedReq struct {
	AgentID       string `json:"agent_id"`
	ClearanceETag string `json:"clearance_etag,omitempty"`
	Nonce         string `json:"nonce"`
	Timestamp     int64  `json:"timestamp"`
	SignatureB64  string `json:"signature_b64"`
	Reason        string `json:"reason,omitempty"`
}

// ---------- errors ----------

type AppError struct {
	Status int
	Code   string
	Msg    string
}

func (e AppError) Error() string { return e.Msg }
func err401(s string) error      { return AppError{Status: 401, Code: errorCode(s), Msg: s} }
func err403(s string) error      { return AppError{Status: 403, Code: errorCode(s), Msg: s} }
func err404(s string) error      { return AppError{Status: 404, Code: errorCode(s), Msg: s + " not found"} }
func err409(s string) error      { return AppError{Status: 409, Code: errorCode(s), Msg: s} }
func err422(s string) error      { return AppError{Status: 422, Code: errorCode(s), Msg: s} }

// ---------- FSM ----------

type Machine struct{ transitions map[State]map[State]bool }

func NewMachine() Machine {
	return Machine{transitions: map[State]map[State]bool{
		StatePending:          {StateAgentsIdentified: true, StateProofSubmitted: true, StateExpired: true},
		StateAgentsIdentified: {StateMandateVerified: true, StateProofSubmitted: true, StateExpired: true},
		StateMandateVerified:  {StateProofSubmitted: true, StateExpired: true},
		StateProofSubmitted:   {StateProofVerified: true, StateDisputed: true, StateExpired: true},
		StateProofVerified:    {StateAccepted: true, StateDisputed: true, StateExpired: true},
		StateAccepted:         {StateReleased: true, StateDisputed: true, StateExpired: true},
		StateDisputed:         {StateResolved: true},
	}}
}

func (m Machine) Transition(c Clearance, to State, t time.Time) (Clearance, error) {
	if terminalState(c.State) {
		return c, err409("clearance terminal")
	}
	if to != StateExpired && clearanceExpired(c, t) {
		return c, err409("clearance expired")
	}
	if !m.transitions[c.State][to] {
		return c, err409("invalid transition " + string(c.State) + " -> " + string(to))
	}
	c.State = to
	c.UpdatedAt = formatTime(t)
	c.History = append(c.History, StateEvent{State: to, Timestamp: c.UpdatedAt})
	return c, nil
}

func terminalState(s State) bool {
	return s == StateReleased || s == StateResolved || s == StateExpired
}
func clearanceExpired(c Clearance, t time.Time) bool {
	if c.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return err == nil && t.UTC().After(exp)
}

// ---------- store ----------

type BoltStore struct{ db *bolt.DB }

func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &BoltStore{db: db}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return rebuildWebhookIndexesTx(tx)
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
func (s *BoltStore) Close() error { return s.db.Close() }
func (s *BoltStore) View(ctx context.Context, fn func(*bolt.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(tx)
	})
}
func (s *BoltStore) Update(ctx context.Context, fn func(*bolt.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(tx)
	})
}

func putJSON[T any](tx *bolt.Tx, bucket []byte, key string, value T) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), raw)
}
func getJSON[T any](tx *bolt.Tx, bucket []byte, key string, out *T) bool {
	v := tx.Bucket(bucket).Get([]byte(key))
	return v != nil && json.Unmarshal(append([]byte(nil), v...), out) == nil
}
func putIndex(tx *bolt.Tx, bucket []byte, key, value string) error {
	return tx.Bucket(bucket).Put([]byte(key), []byte(value))
}
func getU64(tx *bolt.Tx, bucket []byte, key string) uint64 {
	v := tx.Bucket(bucket).Get([]byte(key))
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}
func putU64(tx *bolt.Tx, bucket []byte, key string, v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return tx.Bucket(bucket).Put([]byte(key), buf[:])
}
func getI64(tx *bolt.Tx, bucket []byte, key string) int64 { return int64(getU64(tx, bucket, key)) }
func putI64(tx *bolt.Tx, bucket []byte, key string, v int64) error {
	if v < 0 {
		v = 0
	}
	return putU64(tx, bucket, key, uint64(v))
}
func int64Bytes(v int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	return append([]byte(nil), buf[:]...)
}

func getClearanceTx(tx *bolt.Tx, cid string) (Clearance, error) {
	var c Clearance
	if !getJSON(tx, bClearances, strings.TrimSpace(cid), &c) {
		return c, err404("clearance")
	}
	return c, nil
}

func putClearanceTx(tx *bolt.Tx, c Clearance) error {
	var old Clearance
	if getJSON(tx, bClearances, c.ID, &old) {
		_ = tx.Bucket(bClearByCreated).Delete([]byte(timeIndexKey(old.CreatedAt) + "|" + old.ID))
		_ = tx.Bucket(bClearByState).Delete([]byte(string(old.State) + "|" + timeIndexKey(old.CreatedAt) + "|" + old.ID))
		_ = tx.Bucket(bClearByExpiry).Delete([]byte(timeIndexKey(old.ExpiresAt) + "|" + old.ID))
		if old.MandateID != "" {
			_ = tx.Bucket(bClearByMandateAct).Delete([]byte(old.MandateID + "|" + old.ID))
		}
	}
	if err := putJSON(tx, bClearances, c.ID, c); err != nil {
		return err
	}
	if err := putIndex(tx, bClearByCreated, timeIndexKey(c.CreatedAt)+"|"+c.ID, c.ID); err != nil {
		return err
	}
	if err := putIndex(tx, bClearByState, string(c.State)+"|"+timeIndexKey(c.CreatedAt)+"|"+c.ID, c.ID); err != nil {
		return err
	}
	if !terminalState(c.State) {
		if err := putIndex(tx, bClearByExpiry, timeIndexKey(c.ExpiresAt)+"|"+c.ID, c.ID); err != nil {
			return err
		}
		if c.MandateID != "" {
			if err := putI64(tx, bClearByMandateAct, c.MandateID+"|"+c.ID, c.ValueCents); err != nil {
				return err
			}
		}
	}
	return nil
}

func decrementMandateTx(tx *bolt.Tx, c Clearance) {
	if c.MandateID == "" {
		return
	}
	committed := getI64(tx, bMandateCommitted, c.MandateID) - c.ValueCents
	if committed < 0 {
		committed = 0
	}
	_ = putI64(tx, bMandateCommitted, c.MandateID, committed)
	_ = tx.Bucket(bClearByMandateAct).Delete([]byte(c.MandateID + "|" + c.ID))
}

func (s *BoltStore) appendSystemEventTx(tx *bolt.Tx, requestID, clearanceID, actorID, action, eventType, eventClearanceID string, orgs []string, payload any) error {
	if clearanceID != "" {
		if err := s.appendAuditTx(tx, requestID, clearanceID, actorID, action, payload); err != nil {
			return err
		}
	}
	return s.appendEventTx(tx, eventType, eventClearanceID, actorID, orgs, payload)
}
func (s *BoltStore) appendAuditTx(tx *bolt.Tx, requestID, clearanceID, actorID, action string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	seqKey, headKey := "audit_seq:"+clearanceID, "audit_head:"+clearanceID
	seq := getU64(tx, bMeta, seqKey) + 1
	prev := string(tx.Bucket(bMeta).Get([]byte(headKey)))
	if prev == "" {
		prev = strings.Repeat("0", 64)
	}
	e := ClearanceAuditEntry{ClearanceID: clearanceID, LocalSeq: seq, Timestamp: now(), RequestID: requestID, ActorID: actorID, Action: action, PayloadHash: hash(raw), PrevHash: prev}
	e.Hash = auditHash(e)
	key := fmt.Sprintf("%s|%020d", clearanceID, seq)
	if err := putJSON(tx, bAuditByClearance, key, e); err != nil {
		return err
	}
	if err := putU64(tx, bMeta, seqKey, seq); err != nil {
		return err
	}
	return tx.Bucket(bMeta).Put([]byte(headKey), []byte(e.Hash))
}
func (s *BoltStore) appendEventTx(tx *bolt.Tx, eventType, clearanceID, actorID string, orgs []string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	seq, err := tx.Bucket(bEvents).NextSequence()
	if err != nil {
		return err
	}
	e := Event{ID: id("evt"), Seq: seq, Type: eventType, ClearanceID: clearanceID, ActorID: actorID, OrgIDs: uniq(orgs, 16), Payload: raw, CreatedAt: now()}
	key := fmt.Sprintf("%020d|%s", e.Seq, e.ID)
	if err := putJSON(tx, bEvents, key, e); err != nil {
		return err
	}
	if clearanceID != "" {
		if err := putIndex(tx, bEventsByClearance, clearanceID+"|"+key, key); err != nil {
			return err
		}
	}
	return s.enqueueWebhookDeliveriesTx(tx, e)
}

func indexWebhookTx(tx *bolt.Tx, wh WebhookEndpoint) error {
	if err := putIndex(tx, bWebhooksByOrg, wh.OrgID+"|"+wh.ID, wh.ID); err != nil {
		return err
	}
	events := uniq(wh.Events, 64)
	if len(events) == 0 {
		return putIndex(tx, bWebhooksByOrgEvent, wh.OrgID+"|*|"+wh.ID, wh.ID)
	}
	for _, ev := range events {
		if err := putIndex(tx, bWebhooksByOrgEvent, wh.OrgID+"|"+ev+"|"+wh.ID, wh.ID); err != nil {
			return err
		}
	}
	return nil
}
func rebuildWebhookIndexesTx(tx *bolt.Tx) error {
	for _, b := range [][]byte{bWebhooksByOrg, bWebhooksByOrgEvent} {
		cur := tx.Bucket(b).Cursor()
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			if err := cur.Delete(); err != nil {
				return err
			}
		}
	}
	cur := tx.Bucket(bWebhooks).Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		_ = k
		var wh WebhookEndpoint
		if json.Unmarshal(v, &wh) == nil && wh.Active {
			if err := indexWebhookTx(tx, wh); err != nil {
				return err
			}
		}
	}
	return nil
}
func visitWebhookCandidatesTx(tx *bolt.Tx, orgID, eventType string, seen map[string]bool, fn func(WebhookEndpoint) error) error {
	for _, prefix := range []string{orgID + "|" + eventType + "|", orgID + "|*|"} {
		cur := tx.Bucket(bWebhooksByOrgEvent).Cursor()
		for k, v := cur.Seek([]byte(prefix)); k != nil && bytes.HasPrefix(k, []byte(prefix)); k, v = cur.Next() {
			whID := string(v)
			if seen[whID] {
				continue
			}
			seen[whID] = true
			var wh WebhookEndpoint
			if !getJSON(tx, bWebhooks, whID, &wh) || !wh.Active || wh.OrgID != orgID || !webhookWants(wh, eventType) {
				continue
			}
			if err := fn(wh); err != nil {
				return err
			}
		}
	}
	return nil
}
func webhookWants(wh WebhookEndpoint, typ string) bool {
	if len(wh.Events) == 0 {
		return true
	}
	for _, ev := range wh.Events {
		if ev == typ {
			return true
		}
	}
	return false
}
func (s *BoltStore) enqueueWebhookDeliveriesTx(tx *bolt.Tx, e Event) error {
	if len(e.OrgIDs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, orgID := range e.OrgIDs {
		if err := visitWebhookCandidatesTx(tx, orgID, e.Type, seen, func(wh WebhookEndpoint) error {
			t := time.Now().UTC()
			body := mustJSON(struct {
				ID          string          `json:"id"`
				Event       string          `json:"event"`
				EventID     string          `json:"event_id"`
				ClearanceID string          `json:"clearance_id,omitempty"`
				Timestamp   string          `json:"timestamp"`
				Data        json.RawMessage `json:"data"`
			}{ID: id("whmsg"), Event: e.Type, EventID: e.ID, ClearanceID: e.ClearanceID, Timestamp: formatTime(t), Data: e.Payload})
			d := WebhookDelivery{ID: id("wdl"), EventID: e.ID, Event: e.Type, ClearanceID: e.ClearanceID, WebhookID: wh.ID, OrgID: wh.OrgID, URL: wh.URL, Body: body, Status: "PENDING", NextAttempt: formatTime(t), CreatedAt: formatTime(t), UpdatedAt: formatTime(t)}
			if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
				return err
			}
			return putIndex(tx, bDeliveryDue, deliveryDueKey(d.NextAttempt, d.ID), d.ID)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *BoltStore) RecoverDeliveries(ctx context.Context) error {
	return s.Update(ctx, func(tx *bolt.Tx) error {
		cur := tx.Bucket(bDeliveries).Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			var d WebhookDelivery
			if json.Unmarshal(v, &d) != nil {
				continue
			}
			if d.InFlight || d.Status == "IN_FLIGHT" {
				d.InFlight = false
				d.Status = "PENDING"
				d.NextAttempt = now()
				d.UpdatedAt = now()
				if err := putJSON(tx, bDeliveries, string(k), d); err != nil {
					return err
				}
				if err := putIndex(tx, bDeliveryDue, deliveryDueKey(d.NextAttempt, d.ID), d.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func (s *BoltStore) ClaimDueDeliveries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	limit = clamp(limit, 1, 1000, 100)
	out := []WebhookDelivery{}
	err := s.Update(ctx, func(tx *bolt.Tx) error {
		cur := tx.Bucket(bDeliveryDue).Cursor()
		cutoff := []byte(timeKey(time.Now().UTC()) + "|")
		for k, v := cur.First(); k != nil && bytes.Compare(k, cutoff) <= 0 && len(out) < limit; {
			deliveryID := string(append([]byte(nil), v...))
			if err := cur.Delete(); err != nil {
				return err
			}
			var d WebhookDelivery
			if getJSON(tx, bDeliveries, deliveryID, &d) && d.Status == "PENDING" && !d.InFlight {
				d.Status = "IN_FLIGHT"
				d.InFlight = true
				d.UpdatedAt = now()
				if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
					return err
				}
				out = append(out, d)
			}
			k, v = cur.Next()
		}
		return nil
	})
	return out, err
}
func (s *BoltStore) MarkDeliveryDone(ctx context.Context, id string) error {
	return s.Update(ctx, func(tx *bolt.Tx) error {
		var d WebhookDelivery
		if !getJSON(tx, bDeliveries, id, &d) {
			return nil
		}
		d.Status = "DONE"
		d.InFlight = false
		d.UpdatedAt = now()
		if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
			return err
		}
		_ = tx.Bucket(bDeliveryDead).Delete([]byte(d.ID))
		return putIndex(tx, bDeliveryDone, deliveryDoneKey(d.UpdatedAt, d.ID), d.ID)
	})
}
func (s *BoltStore) MarkDeliveryFailed(ctx context.Context, id, reason string) error {
	return s.Update(ctx, func(tx *bolt.Tx) error {
		var d WebhookDelivery
		if !getJSON(tx, bDeliveries, id, &d) {
			return nil
		}
		d.InFlight = false
		d.Attempts++
		d.LastError = truncate(reason, 512)
		d.UpdatedAt = now()
		if d.Attempts >= maxWebhookAttempts {
			d.Status = "DEAD"
			d.NextAttempt = ""
			if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
				return err
			}
			return putIndex(tx, bDeliveryDead, d.ID, d.ID)
		}
		d.Status = "PENDING"
		d.NextAttempt = formatTime(time.Now().UTC().Add(webhookBackoff(d.Attempts)))
		if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
			return err
		}
		return putIndex(tx, bDeliveryDue, deliveryDueKey(d.NextAttempt, d.ID), d.ID)
	})
}
func webhookBackoff(attempts int) time.Duration {
	shift := attempts
	if shift > 5 {
		shift = 5
	}
	d := time.Duration(30*(1<<shift)) * time.Second
	if d > 15*time.Minute {
		return 15 * time.Minute
	}
	return d
}

// ---------- service ----------

type Service struct {
	store     *BoltStore
	machine   Machine
	authority ed25519.PrivateKey
	clock     func() time.Time
}

func NewService(store *BoltStore, authority ed25519.PrivateKey) *Service {
	return &Service{store: store, machine: NewMachine(), authority: authority, clock: func() time.Time { return time.Now().UTC() }}
}

type CreateOrgCommand struct{ RequestID, Name, Description string }

func (s *Service) CreateOrg(ctx context.Context, cmd CreateOrgCommand) (Organization, error) {
	if err := limitString("name", &cmd.Name, maxShortString, true); err != nil {
		return Organization{}, err
	}
	if err := limitString("description", &cmd.Description, maxLongString, false); err != nil {
		return Organization{}, err
	}
	out := Organization{ID: id("org"), Name: cmd.Name, Description: cmd.Description, CreatedAt: now()}
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		if err := putJSON(tx, bOrgs, out.ID, out); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, cmd.RequestID, "", "system", "ORG_CREATED", "valendir.org.created.v3", "", nil, out)
	})
	return out, err
}

type CreateAgentCommand struct {
	RequestID, OrgID, Role, PublicKeyB64 string
	Scope                                []string
}

func (s *Service) CreateAgent(ctx context.Context, cmd CreateAgentCommand) (Agent, error) {
	if err := limitString("role", &cmd.Role, maxShortString, true); err != nil {
		return Agent{}, err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cmd.PublicKeyB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Agent{}, err422("public_key_b64 must be base64 Ed25519 public key")
	}
	cmd.PublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	var out Agent
	err = s.store.Update(ctx, func(tx *bolt.Tx) error {
		var org Organization
		if !getJSON(tx, bOrgs, strings.TrimSpace(cmd.OrgID), &org) {
			return err404("organization")
		}
		t := now()
		out = Agent{ID: id("agt"), OrgID: org.ID, OrgName: org.Name, Role: cmd.Role, Scope: uniq(cmd.Scope, 64), PublicKeyB64: cmd.PublicKeyB64, Status: "ACTIVE", CreatedAt: t, UpdatedAt: t}
		if err := putJSON(tx, bAgents, out.ID, out); err != nil {
			return err
		}
		if err := putIndex(tx, bAgentsByOrg, org.ID+"|"+out.ID, out.ID); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, cmd.RequestID, "", out.ID, "AGENT_CREATED", "valendir.agent.created.v3", "", []string{org.ID}, map[string]any{"agent_id": out.ID, "org_id": org.ID, "pubkey_fp": hash(pub)[:16]})
	})
	return out, err
}
func (s *Service) SetAgentStatus(ctx context.Context, requestID, agentID, status string) (Agent, error) {
	var out Agent
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		if !getJSON(tx, bAgents, agentID, &out) {
			return err404("agent")
		}
		out.Status = status
		out.UpdatedAt = now()
		if err := putJSON(tx, bAgents, out.ID, out); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, requestID, "", "system", "AGENT_STATUS_CHANGED", "valendir.agent.status_changed.v3", "", []string{out.OrgID}, map[string]string{"agent_id": out.ID, "status": status})
	})
	return out, err
}

type CreateMandateCommand struct {
	RequestID       string
	AgentID         string
	ValueLimitCents int64
	AllowedActions  []string
	Jurisdiction    string
	Policy          string
	DurationDays    int
}

func (s *Service) CreateMandate(ctx context.Context, cmd CreateMandateCommand) (Mandate, error) {
	cmd.AllowedActions = uniq(cmd.AllowedActions, 64)
	if cmd.ValueLimitCents <= 0 || len(cmd.AllowedActions) == 0 {
		return Mandate{}, err422("positive value_limit_cents and allowed_actions required")
	}
	if cmd.DurationDays <= 0 {
		cmd.DurationDays = 90
	}
	if cmd.Policy == "" {
		cmd.Policy = "AUTO_WITHIN_LIMIT"
	}
	if cmd.Jurisdiction == "" {
		cmd.Jurisdiction = "US-COMMERCIAL"
	}
	if err := limitString("policy", &cmd.Policy, maxShortString, true); err != nil {
		return Mandate{}, err
	}
	if err := limitString("jurisdiction", &cmd.Jurisdiction, maxShortString, true); err != nil {
		return Mandate{}, err
	}
	var out Mandate
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		var ag Agent
		if !getJSON(tx, bAgents, strings.TrimSpace(cmd.AgentID), &ag) {
			return err404("agent")
		}
		if ag.Status != "ACTIVE" {
			return err409("agent inactive")
		}
		t := s.clock()
		out = Mandate{ID: id("mnd"), AgentID: ag.ID, OrgID: ag.OrgID, OrgName: ag.OrgName, AgentRole: ag.Role, ValueLimitCents: cmd.ValueLimitCents, AllowedActions: cmd.AllowedActions, Jurisdiction: cmd.Jurisdiction, Policy: cmd.Policy, ExpiresAt: formatTime(t.Add(time.Duration(cmd.DurationDays) * 24 * time.Hour)), Active: true, CreatedAt: formatTime(t)}
		if err := putJSON(tx, bMandates, out.ID, out); err != nil {
			return err
		}
		if err := putIndex(tx, bMandatesByAgent, ag.ID+"|"+out.ID, out.ID); err != nil {
			return err
		}
		if err := putI64(tx, bMandateCommitted, out.ID, 0); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, cmd.RequestID, "", ag.ID, "MANDATE_CREATED", "valendir.mandate.created.v3", "", []string{ag.OrgID}, out)
	})
	return out, err
}
func (s *Service) RevokeMandate(ctx context.Context, requestID, mandateID string) (Mandate, error) {
	var out Mandate
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		if !getJSON(tx, bMandates, mandateID, &out) {
			return err404("mandate")
		}
		out.Active = false
		if err := putJSON(tx, bMandates, out.ID, out); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, requestID, "", "system", "MANDATE_REVOKED", "valendir.mandate.revoked.v3", "", []string{out.OrgID}, map[string]string{"mandate_id": out.ID})
	})
	return out, err
}

type CreateClearanceCommand struct {
	RequestID, BuyerAgentID, SellerAgentID, MandateID, TransactionType, Label string
	IntentDomain, IntentSummary, SystemOfRecord, RiskClass                    string
	RollbackURI, RollbackHash                                                 string
	Constraints                                                               []IntentConstraint
	ValueCents                                                                int64
	TTLSeconds, DefaultTTLDays                                                int
}

func (s *Service) CreateClearance(ctx context.Context, cmd CreateClearanceCommand) (Clearance, error) {
	cmd.BuyerAgentID = strings.TrimSpace(cmd.BuyerAgentID)
	cmd.SellerAgentID = strings.TrimSpace(cmd.SellerAgentID)
	cmd.IntentDomain = strings.ToLower(strings.TrimSpace(cmd.IntentDomain))
	cmd.RiskClass = strings.ToLower(strings.TrimSpace(cmd.RiskClass))
	cmd.MandateID = strings.TrimSpace(cmd.MandateID)
	if err := limitString("transaction_type", &cmd.TransactionType, maxShortString, false); err != nil {
		return Clearance{}, err
	}
	if err := limitString("label", &cmd.Label, maxShortString, false); err != nil {
		return Clearance{}, err
	}
	if cmd.IntentDomain == "" {
		cmd.IntentDomain = "commercial_agent"
	}
	if cmd.RiskClass == "" {
		cmd.RiskClass = "medium"
	}
	if err := limitString("intent_domain", &cmd.IntentDomain, maxShortString, true); err != nil {
		return Clearance{}, err
	}
	if err := limitString("intent_summary", &cmd.IntentSummary, maxLongString, false); err != nil {
		return Clearance{}, err
	}
	if err := limitString("system_of_record", &cmd.SystemOfRecord, maxShortString, false); err != nil {
		return Clearance{}, err
	}
	if err := limitString("risk_class", &cmd.RiskClass, maxShortString, true); err != nil {
		return Clearance{}, err
	}
	if !validIntentDomains[cmd.IntentDomain] {
		return Clearance{}, err422("unsupported intent_domain")
	}
	if !validRiskClasses[cmd.RiskClass] {
		return Clearance{}, err422("unsupported risk_class")
	}
	if len(cmd.Constraints) > maxIntentConstraints {
		return Clearance{}, err422("too many intent constraints")
	}
	for i := range cmd.Constraints {
		if err := normalizeIntentConstraint(&cmd.Constraints[i]); err != nil {
			return Clearance{}, err
		}
	}
	if err := normalizeOptionalURI("rollback_uri", &cmd.RollbackURI); err != nil {
		return Clearance{}, err
	}
	if err := normalizeOptionalSHA256("rollback_hash", &cmd.RollbackHash); err != nil {
		return Clearance{}, err
	}
	if (cmd.RiskClass == "high" || cmd.RiskClass == "critical") && len(cmd.Constraints) == 0 {
		return Clearance{}, err422("constraints required for high or critical risk clearance")
	}
	if (cmd.RiskClass == "high" || cmd.RiskClass == "critical") && cmd.RollbackHash == "" {
		return Clearance{}, err422("rollback_hash required for high or critical risk clearance")
	}
	if cmd.ValueCents < 0 {
		return Clearance{}, err422("non-negative value_cents required")
	}
	if cmd.ValueCents > 0 && cmd.MandateID == "" {
		return Clearance{}, err422("mandate_id required for value-bearing clearance")
	}
	if cmd.TransactionType == "" {
		cmd.TransactionType = "procurement.quote_acceptance"
	}
	if cmd.Label == "" {
		cmd.Label = cmd.TransactionType
	}
	if cmd.TTLSeconds <= 0 {
		cmd.TTLSeconds = cmd.DefaultTTLDays * 24 * 3600
	}
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		var buyer, seller Agent
		if !getJSON(tx, bAgents, cmd.BuyerAgentID, &buyer) {
			return err404("buyer agent")
		}
		if !getJSON(tx, bAgents, cmd.SellerAgentID, &seller) {
			return err404("seller agent")
		}
		if buyer.Status != "ACTIVE" || seller.Status != "ACTIVE" {
			return err409("agent inactive")
		}
		if cmd.MandateID != "" {
			var m Mandate
			if !getJSON(tx, bMandates, cmd.MandateID, &m) {
				return err404("mandate")
			}
			if err := validateMandateAt(m, buyer.ID, cmd.TransactionType, cmd.ValueCents, s.clock()); err != nil {
				return err
			}
			committed := getI64(tx, bMandateCommitted, m.ID)
			if committed+cmd.ValueCents > m.ValueLimitCents {
				return err409(fmt.Sprintf("mandate capacity exceeded: committed %d + requested %d > limit %d", committed, cmd.ValueCents, m.ValueLimitCents))
			}
			if err := putI64(tx, bMandateCommitted, m.ID, committed+cmd.ValueCents); err != nil {
				return err
			}
		}
		t := s.clock()
		out = Clearance{
			ID: id("clr"), BuyerAgentID: buyer.ID, SellerAgentID: seller.ID, MandateID: cmd.MandateID,
			TransactionType: cmd.TransactionType, Label: cmd.Label,
			IntentDomain:   cmd.IntentDomain,
			IntentSummary:  cmd.IntentSummary,
			SystemOfRecord: cmd.SystemOfRecord,
			RiskClass:      cmd.RiskClass,
			Constraints:    cmd.Constraints,
			RollbackURI:    cmd.RollbackURI,
			RollbackHash:   cmd.RollbackHash,
			ValueCents:     cmd.ValueCents,
			TTLSeconds:     cmd.TTLSeconds,
			ExpiresAt:      formatTime(t.Add(time.Duration(cmd.TTLSeconds) * time.Second)),
			State:          StatePending,
			History:        []StateEvent{{State: StatePending, Timestamp: formatTime(t)}},
			CreatedAt:      formatTime(t), UpdatedAt: formatTime(t),
		}
		if err := putClearanceTx(tx, out); err != nil {
			return err
		}
		return s.store.appendSystemEventTx(tx, cmd.RequestID, out.ID, "system", "CLEARANCE_CREATED", EvtClearanceCreated, out.ID, []string{buyer.OrgID, seller.OrgID}, map[string]any{"clearance_id": out.ID, "state": out.State, "intent_domain": out.IntentDomain, "risk_class": out.RiskClass, "system_of_record": out.SystemOfRecord})
	})
	return out, err
}

func (s *Service) IdentifyAgents(ctx context.Context, requestID, ifMatch, clearanceID string) (Clearance, error) {
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		c, err = s.machine.Transition(c, StateAgentsIdentified, s.clock())
		if err != nil {
			return err
		}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "AGENTS_IDENTIFIED", EvtAgentsIdentified, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "buyer_agent_id": c.BuyerAgentID, "seller_agent_id": c.SellerAgentID})
	})
	return out, err
}
func (s *Service) VerifyMandate(ctx context.Context, requestID, ifMatch, clearanceID string) (Clearance, error) {
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		if c.MandateID == "" {
			return err409("clearance has no mandate")
		}
		var m Mandate
		if !getJSON(tx, bMandates, c.MandateID, &m) {
			return err404("mandate")
		}
		if err := validateMandateAt(m, c.BuyerAgentID, c.TransactionType, c.ValueCents, s.clock()); err != nil {
			return err
		}
		c, err = s.machine.Transition(c, StateMandateVerified, s.clock())
		if err != nil {
			return err
		}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, requestID, c.ID, c.BuyerAgentID, "MANDATE_VERIFIED", EvtMandateVerified, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "mandate_id": m.ID, "value_cents": c.ValueCents, "committed_cents": getI64(tx, bMandateCommitted, m.ID)})
	})
	return out, err
}

type SubmitProofCommand struct {
	RequestID, IfMatch, ClearanceID, SubmittedBy, Role string
	Artifacts                                          []Artifact
}

func (s *Service) SubmitProof(ctx context.Context, cmd SubmitProofCommand) (Clearance, ProofBundle, error) {
	cmd.Role = strings.ToLower(strings.TrimSpace(cmd.Role))
	if cmd.Role != "buyer" && cmd.Role != "seller" && cmd.Role != "counterparty" {
		return Clearance{}, ProofBundle{}, err422("role must be buyer, seller, or counterparty")
	}
	if len(cmd.Artifacts) == 0 || len(cmd.Artifacts) > maxArtifactsPerProof {
		return Clearance{}, ProofBundle{}, err422("invalid artifact count")
	}
	for i := range cmd.Artifacts {
		if err := normalizeArtifact(&cmd.Artifacts[i]); err != nil {
			return Clearance{}, ProofBundle{}, err
		}
	}
	proof := ProofBundle{ID: id("prf"), ClearanceID: strings.TrimSpace(cmd.ClearanceID), SubmittedBy: strings.TrimSpace(cmd.SubmittedBy), Role: cmd.Role, Artifacts: cmd.Artifacts, CreatedAt: now()}
	proof.SealHash = hashJSON(map[string]any{"clearance_id": proof.ClearanceID, "submitted_by": proof.SubmittedBy, "role": proof.Role, "artifacts": proof.Artifacts, "created_at": proof.CreatedAt})
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, proof.ClearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(cmd.IfMatch, c); err != nil {
			return err
		}
		if proof.SubmittedBy != c.BuyerAgentID && proof.SubmittedBy != c.SellerAgentID {
			return err403("submitted_by must be clearance party")
		}
		if proof.SubmittedBy == c.BuyerAgentID && proof.Role != "buyer" {
			return err409("buyer must submit role=buyer")
		}
		if proof.SubmittedBy == c.SellerAgentID && proof.Role == "buyer" {
			return err409("seller cannot submit role=buyer")
		}
		for _, pid := range c.ProofBundleIDs {
			var old ProofBundle
			if getJSON(tx, bProofs, pid, &old) && old.SubmittedBy == proof.SubmittedBy && old.Role == proof.Role {
				return err409("duplicate proof submission for agent and role")
			}
		}
		if c.State == StatePending || c.State == StateAgentsIdentified || c.State == StateMandateVerified {
			c, err = s.machine.Transition(c, StateProofSubmitted, s.clock())
			if err != nil {
				return err
			}
		} else if c.State != StateProofSubmitted {
			return err409("proof cannot be submitted in state " + string(c.State))
		}
		if err := putJSON(tx, bProofs, proof.ID, proof); err != nil {
			return err
		}
		if err := putIndex(tx, bProofsByClearance, c.ID+"|"+proof.ID, proof.ID); err != nil {
			return err
		}
		c.ProofBundleIDs = append(c.ProofBundleIDs, proof.ID)
		c.UpdatedAt = now()
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, cmd.RequestID, c.ID, proof.SubmittedBy, "PROOF_SUBMITTED", EvtProofSubmitted, c.ID, clearanceOrgsTx(tx, c), map[string]any{"proof_id": proof.ID, "role": proof.Role, "seal_hash": proof.SealHash})
	})
	return out, proof, err
}
func (s *Service) VerifyProof(ctx context.Context, requestID, ifMatch, clearanceID string) (Clearance, error) {
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		buyerProof, sellerProof := false, false
		seals := []string{}
		for _, pid := range c.ProofBundleIDs {
			var p ProofBundle
			if getJSON(tx, bProofs, pid, &p) {
				buyerProof = buyerProof || (p.SubmittedBy == c.BuyerAgentID && p.Role == "buyer")
				sellerProof = sellerProof || (p.SubmittedBy == c.SellerAgentID && (p.Role == "seller" || p.Role == "counterparty"))
				seals = append(seals, p.SealHash)
			}
		}
		if !buyerProof || !sellerProof {
			return err409("bilateral proof required")
		}
		c, err = s.machine.Transition(c, StateProofVerified, s.clock())
		if err != nil {
			return err
		}
		orgs := clearanceOrgsTx(tx, c)
		if err := s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "PROOF_VERIFIED", EvtProofVerified, c.ID, orgs, map[string]any{"clearance_id": c.ID, "seal_hashes": seals}); err != nil {
			return err
		}
		if c.MandateID != "" {
			var m Mandate
			if getJSON(tx, bMandates, c.MandateID, &m) && m.Active && isAutoAcceptEligible(c, m) {
				if next, e := s.machine.Transition(c, StateAccepted, s.clock()); e == nil {
					c = next
					c.AcceptedBy = "auto:mandate:" + m.ID
					if err := s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "AUTO_ACCEPTED_BY_MANDATE", EvtAccepted, c.ID, orgs, map[string]any{"clearance_id": c.ID, "accepted_by": c.AcceptedBy}); err != nil {
						return err
					}
				}
			}
		}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return nil
	})
	return out, err
}

type SignedActionCommand struct {
	RequestID, IfMatch, ClearanceID, Action string
	Signed                                  signedReq
}

func (s *Service) SignedAction(ctx context.Context, cmd SignedActionCommand) (Clearance, error) {
	cmd.Action = strings.TrimSpace(cmd.Action)
	cmd.ClearanceID = strings.TrimSpace(cmd.ClearanceID)
	cmd.Signed.AgentID = strings.TrimSpace(cmd.Signed.AgentID)
	cmd.Signed.ClearanceETag = strings.TrimSpace(cmd.Signed.ClearanceETag)
	cmd.Signed.Nonce = strings.TrimSpace(cmd.Signed.Nonce)
	cmd.Signed.SignatureB64 = strings.TrimSpace(cmd.Signed.SignatureB64)
	if err := limitString("reason", &cmd.Signed.Reason, maxLongString, false); err != nil {
		return Clearance{}, err
	}
	if cmd.Signed.AgentID == "" || cmd.Signed.ClearanceETag == "" || cmd.Signed.Nonce == "" || cmd.Signed.Timestamp == 0 || cmd.Signed.SignatureB64 == "" {
		return Clearance{}, err422("agent_id, clearance_etag, nonce, timestamp, and signature_b64 required")
	}
	if math.Abs(float64(s.clock().Unix()-cmd.Signed.Timestamp)) > signatureSkewSeconds {
		return Clearance{}, err401("timestamp outside skew")
	}
	var ag Agent
	err := s.store.View(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, cmd.ClearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(cmd.Signed.ClearanceETag, c); err != nil {
			return err
		}
		if !getJSON(tx, bAgents, cmd.Signed.AgentID, &ag) || ag.Status != "ACTIVE" {
			return err401("agent inactive")
		}
		return requireSignedActor(cmd.Action, c, cmd.Signed.AgentID)
	})
	if err != nil {
		return Clearance{}, err
	}
	pub, err := base64.StdEncoding.DecodeString(ag.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Clearance{}, err401("stored public key invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(cmd.Signed.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Clearance{}, err401("signature invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), signingMessage(cmd.Action, cmd.ClearanceID, cmd.Signed.AgentID, cmd.Signed.ClearanceETag, cmd.Signed.Nonce, cmd.Signed.Timestamp), sig) {
		return Clearance{}, err401("signature verification failed")
	}
	var out Clearance
	err = s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, cmd.ClearanceID)
		if err != nil {
			return err
		}
		if cmd.IfMatch != "" && strings.TrimSpace(cmd.IfMatch) != cmd.Signed.ClearanceETag {
			return err409("if-match does not match signed clearance_etag")
		}
		if err := matchVersionStrict(cmd.Signed.ClearanceETag, c); err != nil {
			return err
		}
		if err := requireSignedActor(cmd.Action, c, cmd.Signed.AgentID); err != nil {
			return err
		}
		if !getJSON(tx, bAgents, cmd.Signed.AgentID, &ag) || ag.Status != "ACTIVE" {
			return err401("agent inactive")
		}
		nonceKey := cmd.Signed.AgentID + ":" + cmd.Signed.Nonce
		if tx.Bucket(bNonces).Get([]byte(nonceKey)) != nil {
			return err401("nonce already used")
		}
		if err := tx.Bucket(bNonces).Put([]byte(nonceKey), int64Bytes(s.clock().Unix())); err != nil {
			return err
		}
		to, auditAction, eventType := signedTransitionTargets(cmd.Action)
		old := c
		c, err = s.machine.Transition(c, to, s.clock())
		if err != nil {
			return err
		}
		if to == StateAccepted {
			c.AcceptedBy = cmd.Signed.AgentID
		}
		if to == StateReleased {
			decrementMandateTx(tx, old)
			c.ReleaseEvent = &ReleaseEvent{ID: id("rel"), ClearanceID: c.ID, WebhookEvent: EvtReleased, AcceptedBy: c.AcceptedBy, ReleasedBy: cmd.Signed.AgentID, ValueCents: c.ValueCents, ProofState: "VERIFIED_BILATERAL", ProofSeals: proofSealsTx(tx, c), ReleasedAt: now()}
		}
		if to == StateDisputed {
			c.Dispute = &Dispute{ID: id("dsp"), OpenedBy: cmd.Signed.AgentID, Reason: cmd.Signed.Reason, Status: "OPEN", PacketHash: hashJSON(c), CreatedAt: now()}
		}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, cmd.RequestID, c.ID, cmd.Signed.AgentID, auditAction, eventType, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "state": c.State, "nonce": cmd.Signed.Nonce})
	})
	return out, err
}
func signedTransitionTargets(action string) (State, string, string) {
	switch action {
	case "accept":
		return StateAccepted, "COUNTERPARTY_ACCEPTED", EvtAccepted
	case "release":
		return StateReleased, "RELEASED", EvtReleased
	case "dispute":
		return StateDisputed, "DISPUTED", EvtDisputed
	default:
		return "", "", ""
	}
}
func requireSignedActor(action string, c Clearance, agentID string) error {
	switch action {
	case "accept":
		if agentID != c.SellerAgentID {
			return err403("only seller can accept")
		}
	case "release":
		if agentID != c.BuyerAgentID {
			return err403("only buyer can release")
		}
	case "dispute":
		if agentID != c.BuyerAgentID && agentID != c.SellerAgentID {
			return err403("only clearance parties can dispute")
		}
	default:
		return err422("unsupported signed action")
	}
	return nil
}
func (s *Service) Resolve(ctx context.Context, requestID, ifMatch, clearanceID string) (Clearance, error) {
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		old := c
		c, err = s.machine.Transition(c, StateResolved, s.clock())
		if err != nil {
			return err
		}
		decrementMandateTx(tx, old)
		if c.Dispute != nil {
			c.Dispute.Status = "RESOLVED"
			c.Dispute.ResolvedAt = now()
		}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "RESOLVED", EvtResolved, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "state": c.State})
	})
	return out, err
}
func (s *Service) ForceExpire(ctx context.Context, requestID, ifMatch, clearanceID string) (Clearance, error) {
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		old := c
		c, err = s.machine.Transition(c, StateExpired, s.clock())
		if err != nil {
			return err
		}
		decrementMandateTx(tx, old)
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "EXPIRED", EvtExpired, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "state": c.State})
	})
	return out, err
}
func (s *Service) AdminRelease(ctx context.Context, requestID, ifMatch, clearanceID, reason string) (Clearance, error) {
	if err := limitString("reason", &reason, maxLongString, true); err != nil {
		return Clearance{}, err
	}
	var out Clearance
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		if terminalState(c.State) {
			return err409("clearance terminal")
		}
		oldState := c.State
		decrementMandateTx(tx, c)
		c.State = StateReleased
		c.UpdatedAt = now()
		c.History = append(c.History, StateEvent{State: StateReleased, Timestamp: c.UpdatedAt})
		c.ReleaseEvent = &ReleaseEvent{ID: id("rel"), ClearanceID: c.ID, WebhookEvent: EvtAdminReleased, AcceptedBy: "admin:emergency_override", ReleasedBy: "admin:emergency_override", ValueCents: c.ValueCents, ProofState: "EMERGENCY_RELEASE_OVERRIDE", ProofSeals: proofSealsTx(tx, c), ReleasedAt: now()}
		if err := putClearanceTx(tx, c); err != nil {
			return err
		}
		out = c
		return s.store.appendSystemEventTx(tx, requestID, c.ID, "system", "EMERGENCY_RELEASE_OVERRIDE", EvtAdminReleased, c.ID, clearanceOrgsTx(tx, c), map[string]any{"clearance_id": c.ID, "previous_state": oldState, "reason": reason})
	})
	return out, err
}
func (s *Service) IssueAttestation(ctx context.Context, requestID, ifMatch, clearanceID string) (Attestation, error) {
	var att Attestation
	err := s.store.Update(ctx, func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, clearanceID)
		if err != nil {
			return err
		}
		if err := matchVersionStrict(ifMatch, c); err != nil {
			return err
		}
		decision := "PENDING"
		switch c.State {
		case StateReleased:
			decision = "AUTHORIZED"
		case StateDisputed:
			decision = "HELD"
		case StateExpired:
			decision = "DENIED"
		}
		att = Attestation{Schema: "valendir.attestation.v3", ClearanceID: c.ID, Decision: decision, State: c.State, ValueCents: c.ValueCents, ReasonCodes: reasonCodesTx(tx, c), PacketRoot: packetRootTx(tx, c), IssuedAt: now()}
		if s.authority == nil {
			att.AuthorityID = "dev_unsigned"
			att.SignatureB64 = "UNSIGNED_DEV_MODE"
		} else {
			pub := s.authority.Public().(ed25519.PublicKey)
			att.AuthorityID = "authority_" + hash(pub)[:12]
			sig := ed25519.Sign(s.authority, canonicalAttestationBytes(att))
			att.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
		}
		return s.store.appendAuditTx(tx, requestID, c.ID, "system", "ATTESTATION_ISSUED", att)
	})
	return att, err
}
func canonicalAttestationBytes(att Attestation) []byte {
	return mustJSON(struct {
		Schema      string   `json:"schema"`
		AuthorityID string   `json:"authority_id"`
		ClearanceID string   `json:"clearance_id"`
		Decision    string   `json:"decision"`
		State       State    `json:"state"`
		ValueCents  int64    `json:"value_cents"`
		ReasonCodes []string `json:"reason_codes"`
		PacketRoot  string   `json:"packet_root"`
		IssuedAt    string   `json:"issued_at"`
	}{att.Schema, att.AuthorityID, att.ClearanceID, att.Decision, att.State, att.ValueCents, att.ReasonCodes, att.PacketRoot, att.IssuedAt})
}
func (s *Service) VerifyAttestation(att Attestation) (bool, []string) {
	errs := []string{}
	okSig := false
	if att.Schema != "valendir.attestation.v3" {
		errs = append(errs, "unsupported schema")
	}
	if att.PacketRoot == "" {
		errs = append(errs, "packet_root required")
	}
	if s.authority == nil {
		errs = append(errs, "authority not configured")
	} else {
		sig, err := base64.StdEncoding.DecodeString(att.SignatureB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			errs = append(errs, "bad signature_b64")
		} else {
			pub := s.authority.Public().(ed25519.PublicKey)
			okSig = ed25519.Verify(pub, canonicalAttestationBytes(att), sig)
			if !okSig {
				errs = append(errs, "signature failed")
			}
		}
	}
	return okSig && len(errs) == 0, errs
}

// ---------- service helpers ----------

func validateMandateAt(m Mandate, agentID, action string, value int64, t time.Time) error {
	if m.AgentID != agentID {
		return err409("mandate not bound to buyer")
	}
	if !m.Active {
		return err409("mandate inactive")
	}
	exp, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil || t.UTC().After(exp) {
		return err409("mandate expired")
	}
	if value > m.ValueLimitCents {
		return err409("value exceeds mandate limit")
	}
	for _, a := range m.AllowedActions {
		if a == "*" || strings.EqualFold(a, action) {
			return nil
		}
	}
	return err409("action not allowed by mandate")
}
func isAutoAcceptEligible(c Clearance, m Mandate) bool {
	if !strings.EqualFold(m.Policy, "AUTO_WITHIN_LIMIT") {
		return false
	}
	if c.ValueCents > m.ValueLimitCents {
		return false
	}
	switch c.RiskClass {
	case "", "low", "medium":
		return true
	case "high", "critical":
		return false
	default:
		return false
	}
}
func clearanceOrgsTx(tx *bolt.Tx, c Clearance) []string {
	var b, s Agent
	_ = getJSON(tx, bAgents, c.BuyerAgentID, &b)
	_ = getJSON(tx, bAgents, c.SellerAgentID, &s)
	return uniq([]string{b.OrgID, s.OrgID}, 4)
}
func proofSealsTx(tx *bolt.Tx, c Clearance) []string {
	out := []string{}
	for _, pid := range c.ProofBundleIDs {
		var p ProofBundle
		if getJSON(tx, bProofs, pid, &p) {
			out = append(out, p.SealHash)
		}
	}
	return out
}
func reasonCodesTx(tx *bolt.Tx, c Clearance) []string {
	out := []string{}
	var b, s Agent
	if getJSON(tx, bAgents, c.BuyerAgentID, &b) && getJSON(tx, bAgents, c.SellerAgentID, &s) && b.Status == "ACTIVE" && s.Status == "ACTIVE" {
		out = append(out, "AGENTS_ACTIVE")
	}
	if c.MandateID != "" {
		var m Mandate
		if getJSON(tx, bMandates, c.MandateID, &m) && m.Active {
			out = append(out, "MANDATE_VALID")
			if c.ValueCents <= m.ValueLimitCents {
				out = append(out, "VALUE_WITHIN_LIMIT")
			}
		}
	}
	if len(c.ProofBundleIDs) >= 2 {
		out = append(out, "BILATERAL_PROOF_PRESENT")
	}
	if c.IntentDomain != "" {
		out = append(out, "INTENT_DOMAIN_DECLARED")
	}
	if len(c.Constraints) > 0 {
		out = append(out, "CONSTRAINTS_DECLARED")
	}
	if c.RollbackHash != "" {
		out = append(out, "ROLLBACK_HASH_DECLARED")
	} else if c.RollbackURI != "" {
		out = append(out, "ROLLBACK_URI_DECLARED")
	}
	if c.AcceptedBy != "" {
		out = append(out, "COUNTERPARTY_ACCEPTED")
	}
	if c.ReleaseEvent != nil && c.ReleaseEvent.ProofState == "EMERGENCY_RELEASE_OVERRIDE" {
		out = append(out, "EMERGENCY_RELEASE_OVERRIDE")
	}
	return out
}
func packetRootTx(tx *bolt.Tx, c Clearance) string {
	return hashJSON(map[string]any{"schema": "valendir.packet.v3", "clearance": c, "proof_seals": proofSealsTx(tx, c), "reason_codes": reasonCodesTx(tx, c)})
}

// ---------- API ----------

type App struct {
	cfg     Config
	log     *slog.Logger
	store   *BoltStore
	svc     *Service
	limiter *rateLimiter
	worker  *WebhookDispatcher
}
type ctxKeyRID struct{}
type captureRW struct {
	code     int
	wrote    bool
	capture  bool
	overflow bool
	buf      bytes.Buffer
}

func (w *captureRW) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureRW) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.capture && !w.overflow && w.buf.Len()+len(b) <= maxIdempotencyResponseBody {
		w.buf.Write(b)
	} else if w.capture {
		w.overflow = true
	}
	return w.ResponseWriter.Write(b)
}

func (a *App) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", a.health)
	m.HandleFunc("/.well-known/valendir-authority.pub", a.authorityPub)
	m.HandleFunc("/v1/dev/keypair", a.devKeypair)
	m.HandleFunc("/v1/attestations/verify", a.verifyAttestation)
	m.HandleFunc("/v1/orgs", a.orgs)
	m.HandleFunc("/v1/agents", a.agents)
	m.HandleFunc("/v1/agents/", a.agentSub)
	m.HandleFunc("/v1/mandates", a.mandates)
	m.HandleFunc("/v1/mandates/", a.mandateSub)
	m.HandleFunc("/v1/clearances", a.clearances)
	m.HandleFunc("/v1/clearances/", a.clearanceSub)
	m.HandleFunc("/v1/webhooks", a.webhooks)
	m.HandleFunc("/v1/webhooks/", a.webhookSub)
	m.HandleFunc("/v1/webhook_deliveries", a.deliveryList)
	m.HandleFunc("/v1/webhook_deliveries/", a.deliverySub)
	m.HandleFunc("/v1/events", a.eventList)
	m.HandleFunc("/v1/audit", a.auditList)
	m.HandleFunc("/v1/audit/verify", a.auditVerify)
	m.HandleFunc("/v1/metrics", a.metrics)
	m.HandleFunc("/v1/admin/backup", a.backup)
	return a.middleware(m)
}
func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if a.cfg.CORS != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.cfg.CORS)
			w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type, x-request-id, idempotency-key, if-match")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		rip := clientIP(r)
		if !a.limiter.allow(rip) {
			writeErr(w, 429, "rate limit exceeded")
			return
		}
		rid := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if rid == "" {
			rid = randomID(8)
		}
		w.Header().Set("X-Request-ID", rid)
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyRID{}, rid))
		crw := &captureRW{ResponseWriter: w, code: 200}
		idem := a.beginIdempotency(crw, r)
		if idem.active && idem.replay != nil {
			if idem.replay.ContentType != "" {
				crw.Header().Set("Content-Type", idem.replay.ContentType)
			}
			crw.WriteHeader(idem.replay.ResponseCode)
			_, _ = crw.Write(idem.replay.ResponseBody)
			return
		}
		if idem.active && idem.key == "" {
			return
		}
		if idem.active && idem.key != "" {
			crw.capture = true
		}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				a.log.Error("panic", "rid", rid, "panic", rec)
				if idem.active {
					a.clearIdempotency(idem.key)
				}
				if !crw.wrote || crw.code < 400 {
					writeErr(crw, 500, "internal server error")
				}
			}
			if idem.active && idem.key != "" {
				a.finishIdempotency(idem.key, r, crw)
			}
			a.log.Info("http", "rid", rid, "method", r.Method, "path", r.URL.Path, "status", crw.code, "dur_ms", time.Since(start).Milliseconds(), "ip", rip)
		}()
		next.ServeHTTP(crw, r)
	})
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	if method(w, r, http.MethodGet) {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "valendir-core-v3", "time": now()})
	}
}
func (a *App) authorityPub(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	if a.svc.authority == nil {
		writeErr(w, 404, "authority key not configured")
		return
	}
	pub := a.svc.authority.Public().(ed25519.PublicKey)
	writeJSON(w, 200, map[string]string{"schema": "valendir.authority-key.v3", "algorithm": "Ed25519", "public_key_b64": base64.StdEncoding.EncodeToString(pub), "fingerprint": hash(pub)})
}
func (a *App) devKeypair(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.DevMode {
		writeErr(w, 404, "not found")
		return
	}
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"public_key_b64": base64.StdEncoding.EncodeToString(pub), "private_key_b64": base64.StdEncoding.EncodeToString(priv), "authority_key_env": "VALENDIR_AUTHORITY_KEY=" + base64.StdEncoding.EncodeToString(priv)})
}
func (a *App) orgs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authRead(w, r) {
			return
		}
		page, err := listPage[Organization](r.Context(), a.store, bOrgs, pageQuery(r), nil)
		done(w, 200, page, err)
	case http.MethodPost:
		if !a.authWrite(w, r) {
			return
		}
		var q struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if !decode(w, r, &q) {
			return
		}
		out, err := a.svc.CreateOrg(r.Context(), CreateOrgCommand{RequestID: requestID(r), Name: q.Name, Description: q.Description})
		done(w, 201, out, err)
	default:
		writeErr(w, 405, "method not allowed")
	}
}
func (a *App) agents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authRead(w, r) {
			return
		}
		page, err := listPage[Agent](r.Context(), a.store, bAgents, pageQuery(r), nil)
		done(w, 200, page, err)
	case http.MethodPost:
		if !a.authWrite(w, r) {
			return
		}
		var q struct {
			OrgID        string   `json:"org_id"`
			Role         string   `json:"role"`
			PublicKeyB64 string   `json:"public_key_b64"`
			Scope        []string `json:"scope"`
		}
		if !decode(w, r, &q) {
			return
		}
		out, err := a.svc.CreateAgent(r.Context(), CreateAgentCommand{RequestID: requestID(r), OrgID: q.OrgID, Role: q.Role, Scope: q.Scope, PublicKeyB64: q.PublicKeyB64})
		done(w, 201, out, err)
	default:
		writeErr(w, 405, "method not allowed")
	}
}
func (a *App) agentSub(w http.ResponseWriter, r *http.Request) {
	p := pathParts(r.URL.Path)
	if len(p) < 3 {
		writeErr(w, 404, "not found")
		return
	}
	if len(p) == 3 {
		if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
			return
		}
		var out Agent
		err := a.store.View(r.Context(), func(tx *bolt.Tx) error {
			if !getJSON(tx, bAgents, p[2], &out) {
				return err404("agent")
			}
			return nil
		})
		done(w, 200, out, err)
		return
	}
	if len(p) == 4 && (p[3] == "activate" || p[3] == "deactivate") {
		if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
			return
		}
		status := "INACTIVE"
		if p[3] == "activate" {
			status = "ACTIVE"
		}
		out, err := a.svc.SetAgentStatus(r.Context(), requestID(r), p[2], status)
		done(w, 200, out, err)
		return
	}
	writeErr(w, 404, "unknown agent action")
}
func (a *App) mandates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authRead(w, r) {
			return
		}
		page, err := listPage[Mandate](r.Context(), a.store, bMandates, pageQuery(r), nil)
		done(w, 200, page, err)
	case http.MethodPost:
		if !a.authWrite(w, r) {
			return
		}
		var q struct {
			AgentID         string   `json:"agent_id"`
			ValueLimitCents int64    `json:"value_limit_cents"`
			AllowedActions  []string `json:"allowed_actions"`
			Jurisdiction    string   `json:"jurisdiction"`
			Policy          string   `json:"policy"`
			DurationDays    int      `json:"duration_days"`
		}
		if !decode(w, r, &q) {
			return
		}
		out, err := a.svc.CreateMandate(r.Context(), CreateMandateCommand{RequestID: requestID(r), AgentID: q.AgentID, ValueLimitCents: q.ValueLimitCents, AllowedActions: q.AllowedActions, Jurisdiction: q.Jurisdiction, Policy: q.Policy, DurationDays: q.DurationDays})
		done(w, 201, out, err)
	default:
		writeErr(w, 405, "method not allowed")
	}
}
func (a *App) mandateSub(w http.ResponseWriter, r *http.Request) {
	p := pathParts(r.URL.Path)
	if len(p) == 3 {
		if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
			return
		}
		var out Mandate
		err := a.store.View(r.Context(), func(tx *bolt.Tx) error {
			if !getJSON(tx, bMandates, p[2], &out) {
				return err404("mandate")
			}
			return nil
		})
		done(w, 200, out, err)
		return
	}
	if len(p) == 4 && p[3] == "revoke" {
		if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
			return
		}
		out, err := a.svc.RevokeMandate(r.Context(), requestID(r), p[2])
		done(w, 200, out, err)
		return
	}
	writeErr(w, 404, "unknown mandate action")
}
func (a *App) clearances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authRead(w, r) {
			return
		}
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if state != "" {
			page, err := listIndexPage[Clearance](r.Context(), a.store, bClearByState, bClearances, state+"|", pageQuery(r), true, nil)
			done(w, 200, page, err)
			return
		}
		page, err := listIndexPage[Clearance](r.Context(), a.store, bClearByCreated, bClearances, "", pageQuery(r), true, nil)
		done(w, 200, page, err)
	case http.MethodPost:
		if !a.authWrite(w, r) {
			return
		}
		var q struct {
			BuyerAgentID    string             `json:"buyer_agent_id"`
			SellerAgentID   string             `json:"seller_agent_id"`
			MandateID       string             `json:"mandate_id"`
			TransactionType string             `json:"transaction_type"`
			Label           string             `json:"label"`
			IntentDomain    string             `json:"intent_domain"`
			IntentSummary   string             `json:"intent_summary"`
			SystemOfRecord  string             `json:"system_of_record"`
			RiskClass       string             `json:"risk_class"`
			Constraints     []IntentConstraint `json:"constraints"`
			RollbackURI     string             `json:"rollback_uri"`
			RollbackHash    string             `json:"rollback_hash"`
			ValueCents      int64              `json:"value_cents"`
			TTLSeconds      int                `json:"ttl_seconds"`
		}
		if !decode(w, r, &q) {
			return
		}
		out, err := a.svc.CreateClearance(r.Context(), CreateClearanceCommand{
			RequestID: requestID(r), BuyerAgentID: q.BuyerAgentID, SellerAgentID: q.SellerAgentID,
			MandateID: q.MandateID, TransactionType: q.TransactionType, Label: q.Label,
			IntentDomain: q.IntentDomain, IntentSummary: q.IntentSummary, SystemOfRecord: q.SystemOfRecord,
			RiskClass: q.RiskClass, Constraints: q.Constraints, RollbackURI: q.RollbackURI, RollbackHash: q.RollbackHash,
			ValueCents: q.ValueCents, TTLSeconds: q.TTLSeconds, DefaultTTLDays: a.cfg.TTLDays,
		})
		done(w, 201, out, err)
	default:
		writeErr(w, 405, "method not allowed")
	}
}
func (a *App) clearanceSub(w http.ResponseWriter, r *http.Request) {
	p := pathParts(r.URL.Path)
	if len(p) < 3 {
		writeErr(w, 404, "not found")
		return
	}
	cid := p[2]
	if len(p) == 3 {
		if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
			return
		}
		a.getClearance(w, r, cid)
		return
	}
	switch p[3] {
	case "identify":
		a.identify(w, r, cid)
	case "verify-mandate":
		a.verifyMandate(w, r, cid)
	case "proofs":
		a.submitProof(w, r, cid)
	case "verify-proof":
		a.verifyProof(w, r, cid)
	case "sign-message":
		a.signMessage(w, r, cid)
	case "accept", "release", "dispute":
		a.signedAction(w, r, cid, p[3])
	case "resolve":
		a.resolve(w, r, cid)
	case "expire":
		a.forceExpire(w, r, cid)
	case "admin-release":
		a.adminRelease(w, r, cid)
	case "attestation":
		a.attestation(w, r, cid)
	default:
		writeErr(w, 404, "unknown clearance action")
	}
}
func (a *App) getClearance(w http.ResponseWriter, r *http.Request, cid string) {
	var c Clearance
	proofs := []ProofBundle{}
	err := a.store.View(r.Context(), func(tx *bolt.Tx) error {
		var err error
		c, err = getClearanceTx(tx, cid)
		if err != nil {
			return err
		}
		for _, pid := range c.ProofBundleIDs {
			var p ProofBundle
			if getJSON(tx, bProofs, pid, &p) {
				proofs = append(proofs, p)
			}
		}
		return nil
	})
	if err == nil {
		w.Header().Set("ETag", clearanceETag(c))
	}
	done(w, 200, map[string]any{"clearance": c, "proofs": proofs}, err)
}
func (a *App) identify(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	out, err := a.svc.IdentifyAgents(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, out, err)
}
func (a *App) verifyMandate(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	out, err := a.svc.VerifyMandate(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, out, err)
}
func (a *App) submitProof(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	var q struct {
		SubmittedBy string     `json:"submitted_by"`
		Role        string     `json:"role"`
		Artifacts   []Artifact `json:"artifacts"`
	}
	if !decode(w, r, &q) {
		return
	}
	c, p, err := a.svc.SubmitProof(r.Context(), SubmitProofCommand{RequestID: requestID(r), IfMatch: r.Header.Get("If-Match"), ClearanceID: cid, SubmittedBy: q.SubmittedBy, Role: q.Role, Artifacts: q.Artifacts})
	done(w, 201, map[string]any{"clearance": c, "proof": p}, err)
}
func (a *App) verifyProof(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	out, err := a.svc.VerifyProof(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, out, err)
}
func (a *App) signMessage(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	action, agentID := strings.TrimSpace(r.URL.Query().Get("action")), strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if action != "accept" && action != "release" && action != "dispute" {
		writeErr(w, 422, "action must be accept, release, or dispute")
		return
	}
	var etag string
	err := a.store.View(r.Context(), func(tx *bolt.Tx) error {
		c, err := getClearanceTx(tx, cid)
		if err != nil {
			return err
		}
		etag = clearanceETag(c)
		return requireSignedActor(action, c, agentID)
	})
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	nonce := hex.EncodeToString(randomBytes(20))
	ts := time.Now().UTC().Unix()
	msg := signingMessage(action, cid, agentID, etag, nonce, ts)
	writeJSON(w, 200, map[string]any{"action": action, "clearance_id": cid, "agent_id": agentID, "clearance_etag": etag, "nonce": nonce, "timestamp": ts, "message_b64": base64.StdEncoding.EncodeToString(msg), "message_text": string(msg)})
}
func (a *App) signedAction(w http.ResponseWriter, r *http.Request, cid, action string) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var q signedReq
	if !decode(w, r, &q) {
		return
	}
	out, err := a.svc.SignedAction(r.Context(), SignedActionCommand{RequestID: requestID(r), IfMatch: r.Header.Get("If-Match"), ClearanceID: cid, Action: action, Signed: q})
	done(w, 200, out, err)
}
func (a *App) resolve(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	out, err := a.svc.Resolve(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, out, err)
}
func (a *App) forceExpire(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	out, err := a.svc.ForceExpire(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, out, err)
}
func (a *App) adminRelease(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authEmergency(w, r) {
		return
	}
	var q struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &q) {
		return
	}
	out, err := a.svc.AdminRelease(r.Context(), requestID(r), r.Header.Get("If-Match"), cid, q.Reason)
	done(w, 200, out, err)
}
func (a *App) attestation(w http.ResponseWriter, r *http.Request, cid string) {
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	att, err := a.svc.IssueAttestation(r.Context(), requestID(r), r.Header.Get("If-Match"), cid)
	done(w, 200, att, err)
}
func (a *App) verifyAttestation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var att Attestation
	if !decode(w, r, &att) {
		return
	}
	ok, errs := a.svc.VerifyAttestation(att)
	writeJSON(w, choose(ok, 200, 400), map[string]any{"verified": ok, "errors": errs})
}

func (a *App) webhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authRead(w, r) {
			return
		}
		page, err := listPage[WebhookEndpoint](r.Context(), a.store, bWebhooks, pageQuery(r), func(wh *WebhookEndpoint) { wh.Secret = "" })
		done(w, 200, page, err)
	case http.MethodPost:
		if !a.authWrite(w, r) {
			return
		}
		var q struct {
			OrgID  string   `json:"org_id"`
			URL    string   `json:"url"`
			Secret string   `json:"secret"`
			Events []string `json:"events"`
		}
		if !decode(w, r, &q) {
			return
		}
		if err := validateWebhookURL(q.URL); err != nil {
			writeErr(w, 422, err.Error())
			return
		}
		if q.Secret == "" {
			q.Secret = token()
		}
		if len(q.Secret) < 24 {
			writeErr(w, 422, "secret must be at least 24 characters")
			return
		}
		var out WebhookEndpoint
		err := a.store.Update(r.Context(), func(tx *bolt.Tx) error {
			var org Organization
			if !getJSON(tx, bOrgs, strings.TrimSpace(q.OrgID), &org) {
				return err404("organization")
			}
			out = WebhookEndpoint{ID: id("wh"), OrgID: org.ID, URL: q.URL, Secret: q.Secret, Events: uniq(q.Events, 64), Active: true, CreatedAt: now()}
			if err := putJSON(tx, bWebhooks, out.ID, out); err != nil {
				return err
			}
			if err := indexWebhookTx(tx, out); err != nil {
				return err
			}
			return a.store.appendSystemEventTx(tx, requestID(r), "", "system", "WEBHOOK_CREATED", "valendir.webhook.created.v3", "", []string{org.ID}, map[string]any{"webhook_id": out.ID, "org_id": org.ID})
		})
		done(w, 201, out, err)
	default:
		writeErr(w, 405, "method not allowed")
	}
}
func (a *App) webhookSub(w http.ResponseWriter, r *http.Request) {
	p := pathParts(r.URL.Path)
	if len(p) != 3 {
		writeErr(w, 404, "not found")
		return
	}
	if !method(w, r, http.MethodDelete) || !a.authWrite(w, r) {
		return
	}
	err := a.store.Update(r.Context(), func(tx *bolt.Tx) error {
		var wh WebhookEndpoint
		if !getJSON(tx, bWebhooks, p[2], &wh) {
			return err404("webhook")
		}
		wh.Active = false
		if err := putJSON(tx, bWebhooks, wh.ID, wh); err != nil {
			return err
		}
		return a.store.appendSystemEventTx(tx, requestID(r), "", "system", "WEBHOOK_DISABLED", "valendir.webhook.disabled.v3", "", []string{wh.OrgID}, map[string]string{"webhook_id": wh.ID})
	})
	done(w, 200, map[string]string{"disabled": p[2]}, err)
}
func (a *App) deliveryList(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	page, err := listPage[WebhookDelivery](r.Context(), a.store, bDeliveries, pageQuery(r), func(d *WebhookDelivery) { d.Body = nil })
	done(w, 200, page, err)
}
func (a *App) deliverySub(w http.ResponseWriter, r *http.Request) {
	p := pathParts(r.URL.Path)
	if len(p) != 4 || p[3] != "retry" {
		writeErr(w, 404, "not found")
		return
	}
	if !method(w, r, http.MethodPost) || !a.authWrite(w, r) {
		return
	}
	err := a.store.Update(r.Context(), func(tx *bolt.Tx) error {
		var d WebhookDelivery
		if !getJSON(tx, bDeliveries, p[2], &d) {
			return err404("webhook delivery")
		}
		d.Status, d.InFlight, d.Attempts, d.LastError, d.NextAttempt, d.UpdatedAt = "PENDING", false, 0, "", now(), now()
		if err := putJSON(tx, bDeliveries, d.ID, d); err != nil {
			return err
		}
		_ = tx.Bucket(bDeliveryDead).Delete([]byte(d.ID))
		return putIndex(tx, bDeliveryDue, deliveryDueKey(d.NextAttempt, d.ID), d.ID)
	})
	done(w, 200, map[string]string{"retried": p[2]}, err)
}
func (a *App) eventList(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	page, err := listPage[Event](r.Context(), a.store, bEvents, pageQuery(r), nil)
	done(w, 200, page, err)
}
func (a *App) auditList(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	cid := strings.TrimSpace(r.URL.Query().Get("clearance_id"))
	if cid == "" {
		writeErr(w, 422, "clearance_id required")
		return
	}
	page, err := listPrefixedValuePage[ClearanceAuditEntry](r.Context(), a.store, bAuditByClearance, cid+"|", pageQuery(r))
	done(w, 200, page, err)
}
func (a *App) auditVerify(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	cid := strings.TrimSpace(r.URL.Query().Get("clearance_id"))
	if cid == "" {
		writeErr(w, 422, "clearance_id required")
		return
	}
	ok, count, reason := a.verifyClearanceAudit(r.Context(), cid)
	writeJSON(w, 200, map[string]any{"valid": ok, "count_or_broken_at": count, "reason": reason})
}
func (a *App) verifyClearanceAudit(ctx context.Context, cid string) (bool, int, string) {
	ok, at, reason := true, 0, "ok"
	_ = a.store.View(ctx, func(tx *bolt.Tx) error {
		prev := strings.Repeat("0", 64)
		prefix := []byte(cid + "|")
		cur := tx.Bucket(bAuditByClearance).Cursor()
		for k, v := cur.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cur.Next() {
			var e ClearanceAuditEntry
			if json.Unmarshal(v, &e) != nil {
				ok, reason = false, "bad_json"
				return nil
			}
			if e.PrevHash != prev {
				ok, reason = false, "chain_broken"
				return nil
			}
			if auditHash(e) != e.Hash {
				ok, reason = false, "hash_mismatch"
				return nil
			}
			prev = e.Hash
			at++
		}
		return nil
	})
	return ok, at, reason
}
func (a *App) metrics(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) || !a.authRead(w, r) {
		return
	}
	counts := map[string]int{}
	_ = a.store.View(r.Context(), func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			counts[string(b)] = tx.Bucket(b).Stats().KeyN
		}
		return nil
	})
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(200)
	for k, v := range counts {
		_, _ = fmt.Fprintf(w, "valendir_bucket_keys{bucket=%q} %d\n", k, v)
	}
	if st, err := os.Stat(a.cfg.DBPath); err == nil {
		_, _ = fmt.Fprintf(w, "valendir_db_size_bytes %d\n", st.Size())
	}
}
func (a *App) backup(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) || !a.authEmergency(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="valendir.bbolt"`)
	if err := a.store.View(r.Context(), func(tx *bolt.Tx) error { _, err := tx.WriteTo(w); return err }); err != nil {
		a.log.Error("backup failed", "err", err)
	}
}

// ---------- pagination ----------

func listPage[T any](ctx context.Context, store *BoltStore, bucket []byte, q PageQuery, scrub func(*T)) (Page[T], error) {
	q.Limit = clamp(q.Limit, 1, 500, 100)
	out := Page[T]{Items: []T{}}
	err := store.View(ctx, func(tx *bolt.Tx) error {
		cur := tx.Bucket(bucket).Cursor()
		k, v := cursorStartForward(cur, q.Cursor)
		for ; k != nil && len(out.Items) < q.Limit; k, v = cur.Next() {
			var item T
			if err := json.Unmarshal(append([]byte(nil), v...), &item); err != nil {
				return err
			}
			if scrub != nil {
				scrub(&item)
			}
			out.Items = append(out.Items, item)
			out.NextCursor = encodeCursor(k)
		}
		out.Count = len(out.Items)
		return nil
	})
	return out, err
}
func listIndexPage[T any](ctx context.Context, store *BoltStore, indexBucket, entityBucket []byte, prefix string, q PageQuery, reverse bool, scrub func(*T)) (Page[T], error) {
	q.Limit = clamp(q.Limit, 1, 500, 100)
	out := Page[T]{Items: []T{}}
	err := store.View(ctx, func(tx *bolt.Tx) error {
		cur := tx.Bucket(indexBucket).Cursor()
		var k, v []byte
		if reverse {
			k, v = cursorStartReverse(cur, q.Cursor, prefix)
		} else if q.Cursor != "" {
			k, v = cursorStartForward(cur, q.Cursor)
		} else if prefix != "" {
			k, v = cur.Seek([]byte(prefix))
		} else {
			k, v = cur.First()
		}
		for k != nil && len(out.Items) < q.Limit {
			if prefix != "" && !bytes.HasPrefix(k, []byte(prefix)) {
				break
			}
			var item T
			if getJSON(tx, entityBucket, string(v), &item) {
				if scrub != nil {
					scrub(&item)
				}
				out.Items = append(out.Items, item)
				out.NextCursor = encodeCursor(k)
			}
			if reverse {
				k, v = cur.Prev()
			} else {
				k, v = cur.Next()
			}
		}
		out.Count = len(out.Items)
		return nil
	})
	return out, err
}
func listPrefixedValuePage[T any](ctx context.Context, store *BoltStore, bucket []byte, prefix string, q PageQuery) (Page[T], error) {
	q.Limit = clamp(q.Limit, 1, 500, 100)
	out := Page[T]{Items: []T{}}
	err := store.View(ctx, func(tx *bolt.Tx) error {
		cur := tx.Bucket(bucket).Cursor()
		var k, v []byte
		if q.Cursor != "" {
			k, v = cursorStartForward(cur, q.Cursor)
		} else {
			k, v = cur.Seek([]byte(prefix))
		}
		for ; k != nil && len(out.Items) < q.Limit; k, v = cur.Next() {
			if !bytes.HasPrefix(k, []byte(prefix)) {
				break
			}
			var item T
			if err := json.Unmarshal(append([]byte(nil), v...), &item); err != nil {
				return err
			}
			out.Items = append(out.Items, item)
			out.NextCursor = encodeCursor(k)
		}
		out.Count = len(out.Items)
		return nil
	})
	return out, err
}
func cursorStartForward(c *bolt.Cursor, cursor string) ([]byte, []byte) {
	if cursor == "" {
		return c.First()
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return c.First()
	}
	k, v := c.Seek(raw)
	if k == nil {
		return nil, nil
	}
	if bytes.Equal(k, raw) {
		return c.Next()
	}
	return k, v
}
func cursorStartReverse(c *bolt.Cursor, cursor, prefix string) ([]byte, []byte) {
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err == nil {
			k, _ := c.Seek(raw)
			if k == nil {
				return c.Last()
			}
			return c.Prev()
		}
	}
	if prefix != "" {
		seek := append([]byte(prefix), 0xff)
		k, _ := c.Seek(seek)
		if k == nil {
			return c.Last()
		}
		return c.Prev()
	}
	return c.Last()
}
func encodeCursor(k []byte) string {
	if len(k) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(append([]byte(nil), k...))
}

// ---------- idempotency ----------

type IdempotencyRecord struct {
	Key, Subject, Method, Route, RequestHash, Status string
	ResponseCode                                     int
	ContentType                                      string `json:"content_type,omitempty"`
	ResponseBody                                     []byte `json:"response_body,omitempty"`
	CreatedAt, UpdatedAt                             string
}
type idempotencyOutcome struct {
	active bool
	key    string
	replay *IdempotencyRecord
	body   []byte
}

func (a *App) beginIdempotency(w http.ResponseWriter, r *http.Request) idempotencyOutcome {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || !isMutation(r.Method) {
		return idempotencyOutcome{}
	}
	if !idempotencyAllowed(r.Method, r.URL.Path) {
		return idempotencyOutcome{}
	}
	if len(key) > maxShortString {
		writeErr(w, 422, "idempotency key too long")
		return idempotencyOutcome{active: true}
	}
	body, err := readAndRestoreBody(r)
	if err != nil {
		writeErr(w, 413, err.Error())
		return idempotencyOutcome{active: true}
	}
	subject, route, reqHash := a.subjectForRequest(r, body), routeScope(r.URL.Path), hash(body)
	storageKey := hash([]byte(subject + "|" + r.Method + "|" + route + "|" + key))
	var rec IdempotencyRecord
	var replay bool
	err = a.store.Update(r.Context(), func(tx *bolt.Tx) error {
		if getJSON(tx, bIdempotency, storageKey, &rec) {
			if rec.RequestHash != reqHash {
				return err409("idempotency key reused with different request")
			}
			if rec.Status == "IN_PROGRESS" {
				return AppError{Status: 202, Code: "IDEMPOTENCY_IN_PROGRESS", Msg: "idempotency key already in progress"}
			}
			if rec.Status == "SUCCEEDED" {
				replay = true
			}
			return nil
		}
		t := now()
		rec = IdempotencyRecord{Key: storageKey, Subject: subject, Method: r.Method, Route: route, RequestHash: reqHash, Status: "IN_PROGRESS", CreatedAt: t, UpdatedAt: t}
		if err := putJSON(tx, bIdempotency, storageKey, rec); err != nil {
			return err
		}
		return putIndex(tx, bIdempotencyByTime, timeIndexKey(t)+"|"+storageKey, storageKey)
	})
	if err != nil {
		var ae AppError
		if errors.As(err, &ae) && ae.Status == 202 {
			w.Header().Set("Retry-After", "2")
		}
		writeDomainErr(w, err)
		return idempotencyOutcome{active: true, body: body}
	}
	if replay {
		return idempotencyOutcome{active: true, key: storageKey, replay: &rec, body: body}
	}
	return idempotencyOutcome{active: true, key: storageKey, body: body}
}
func (a *App) finishIdempotency(key string, r *http.Request, rw *captureRW) {
	if key == "" {
		return
	}
	_ = a.store.Update(context.Background(), func(tx *bolt.Tx) error {
		var old IdempotencyRecord
		if !getJSON(tx, bIdempotency, key, &old) {
			return nil
		}
		if rw.code >= 200 && rw.code < 300 {
			if rw.overflow {
				return tx.Bucket(bIdempotency).Delete([]byte(key))
			}
			old.Status, old.ResponseCode, old.ContentType, old.ResponseBody, old.UpdatedAt = "SUCCEEDED", rw.code, rw.Header().Get("Content-Type"), append([]byte(nil), rw.buf.Bytes()...), now()
			return putJSON(tx, bIdempotency, key, old)
		}
		return tx.Bucket(bIdempotency).Delete([]byte(key))
	})
}
func (a *App) clearIdempotency(key string) {
	if key != "" {
		_ = a.store.Update(context.Background(), func(tx *bolt.Tx) error { return tx.Bucket(bIdempotency).Delete([]byte(key)) })
	}
}
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("request body too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// ---------- auth/http helpers ----------

func (a *App) authRead(w http.ResponseWriter, r *http.Request) bool {
	return a.auth(w, r, a.cfg.ReadToken, a.cfg.WriteToken, a.cfg.EmergencyToken)
}
func (a *App) authWrite(w http.ResponseWriter, r *http.Request) bool {
	return a.auth(w, r, a.cfg.WriteToken)
}
func (a *App) authEmergency(w http.ResponseWriter, r *http.Request) bool {
	return a.auth(w, r, a.cfg.EmergencyToken)
}
func (a *App) auth(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		writeErr(w, 401, "missing bearer token")
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	for _, want := range allowed {
		if want != "" && hmac.Equal([]byte(got), []byte(want)) {
			return true
		}
	}
	writeErr(w, 401, "invalid bearer token")
	return false
}
func (a *App) subjectForRequest(r *http.Request, body []byte) string {
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
		switch {
		case a.cfg.EmergencyToken != "" && hmac.Equal([]byte(got), []byte(a.cfg.EmergencyToken)):
			return "admin:emergency"
		case a.cfg.WriteToken != "" && hmac.Equal([]byte(got), []byte(a.cfg.WriteToken)):
			return "admin:write"
		case a.cfg.ReadToken != "" && hmac.Equal([]byte(got), []byte(a.cfg.ReadToken)):
			return "admin:read"
		}
	}
	if strings.Contains(r.URL.Path, "/accept") || strings.Contains(r.URL.Path, "/release") || strings.Contains(r.URL.Path, "/dispute") {
		var q signedReq
		if json.Unmarshal(body, &q) == nil && strings.TrimSpace(q.AgentID) != "" {
			return "agent:" + strings.TrimSpace(q.AgentID)
		}
	}
	return "anonymous"
}
func method(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method == m {
		return true
	}
	w.Header().Set("Allow", m)
	writeErr(w, 405, "method not allowed")
	return false
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeErr(w, 400, err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeErr(w, 400, "body must contain one JSON value")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"status": status, "code": errorCode(msg), "message": msg}})
}
func writeAppErr(w http.ResponseWriter, e AppError) {
	code := e.Code
	if code == "" {
		code = errorCode(e.Msg)
	}
	writeJSON(w, e.Status, map[string]any{"error": map[string]any{"status": e.Status, "code": code, "message": e.Msg}})
}
func done(w http.ResponseWriter, code int, v any, err error) {
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, code, v)
}
func writeDomainErr(w http.ResponseWriter, err error) {
	var e AppError
	if errors.As(err, &e) {
		writeAppErr(w, e)
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, 499, err.Error())
		return
	}
	writeErr(w, 500, err.Error())
}
func requestID(r *http.Request) string { s, _ := r.Context().Value(ctxKeyRID{}).(string); return s }
func pageQuery(r *http.Request) PageQuery {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return PageQuery{Limit: limit, Cursor: r.URL.Query().Get("cursor")}
}

// ---------- validation/crypto ----------

func normalizeArtifact(a *Artifact) error {
	a.Name, a.Type, a.SHA256, a.URI = strings.TrimSpace(a.Name), strings.ToLower(strings.TrimSpace(a.Type)), strings.ToLower(strings.TrimSpace(a.SHA256)), strings.TrimSpace(a.URI)
	if err := limitString("artifact.name", &a.Name, maxShortString, true); err != nil {
		return err
	}
	if err := limitString("artifact.uri", &a.URI, maxURIString, false); err != nil {
		return err
	}
	if a.URI != "" {
		u, err := url.Parse(a.URI)
		if err != nil || !allowedArtifactSchemes[strings.ToLower(u.Scheme)] {
			return err422("artifact uri scheme not allowed")
		}
	}
	if a.Type != "" && !validArtifactTypes[a.Type] {
		return err422("invalid artifact type")
	}
	raw, err := hex.DecodeString(a.SHA256)
	if err != nil || len(raw) != sha256.Size {
		return err422("sha256 must be 64 hex characters")
	}
	return nil
}

func normalizeIntentConstraint(c *IntentConstraint) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
	c.Operator = strings.TrimSpace(c.Operator)
	c.Value = strings.TrimSpace(c.Value)
	c.EvidenceSHA256 = strings.ToLower(strings.TrimSpace(c.EvidenceSHA256))
	c.Notes = strings.TrimSpace(c.Notes)
	if c.Kind == "" {
		c.Kind = "policy"
	}
	if !validConstraintKinds[c.Kind] {
		return err422("unsupported constraint kind")
	}
	if err := limitString("constraint.name", &c.Name, maxShortString, true); err != nil {
		return err
	}
	if err := limitString("constraint.kind", &c.Kind, maxShortString, true); err != nil {
		return err
	}
	if err := limitString("constraint.operator", &c.Operator, maxShortString, false); err != nil {
		return err
	}
	if err := limitString("constraint.value", &c.Value, maxShortString, false); err != nil {
		return err
	}
	if err := limitString("constraint.notes", &c.Notes, maxLongString, false); err != nil {
		return err
	}
	if c.EvidenceSHA256 != "" {
		raw, err := hex.DecodeString(c.EvidenceSHA256)
		if err != nil || len(raw) != sha256.Size {
			return err422("constraint evidence_sha256 must be 64 hex characters")
		}
	}
	return nil
}

func normalizeOptionalURI(name string, p *string) error {
	*p = strings.TrimSpace(*p)
	if *p == "" {
		return nil
	}
	if err := limitString(name, p, maxURIString, false); err != nil {
		return err
	}
	u, err := url.Parse(*p)
	if err != nil || !allowedArtifactSchemes[strings.ToLower(u.Scheme)] {
		return err422(name + " scheme not allowed")
	}
	return nil
}

func normalizeOptionalSHA256(name string, p *string) error {
	*p = strings.ToLower(strings.TrimSpace(*p))
	if *p == "" {
		return nil
	}
	raw, err := hex.DecodeString(*p)
	if err != nil || len(raw) != sha256.Size {
		return err422(name + " must be 64 hex characters")
	}
	return nil
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.User != nil || u.Hostname() == "" {
		return errors.New("invalid webhook url")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && env("VALENDIR_ALLOW_INSECURE_WEBHOOKS", "") == "true" {
		return nil
	}
	return errors.New("webhook url must be https")
}
func signingMessage(action, cid, aid, clearanceETag, nonce string, ts int64) []byte {
	return []byte(fmt.Sprintf("valendir/v3\n%s\n%s\n%s\n%s\n%s\n%d", action, cid, aid, clearanceETag, nonce, ts))
}
func auditHash(e ClearanceAuditEntry) string {
	raw := mustJSON(struct {
		ClearanceID                                                  string `json:"clearance_id"`
		LocalSeq                                                     uint64 `json:"local_seq"`
		Timestamp, RequestID, ActorID, Action, PayloadHash, PrevHash string
	}{e.ClearanceID, e.LocalSeq, e.Timestamp, e.RequestID, e.ActorID, e.Action, e.PayloadHash, e.PrevHash})
	return hash(raw)
}
func clearanceETag(c Clearance) string {
	return `"` + hash([]byte(c.ID+"|"+string(c.State)+"|"+c.UpdatedAt+"|"+strconv.FormatInt(c.ValueCents, 10))) + `"`
}
func matchVersion(ifMatch string, c Clearance) error {
	want := strings.TrimSpace(ifMatch)
	if want == "" || want == "*" {
		return nil
	}
	if want != clearanceETag(c) {
		return err409("clearance version mismatch")
	}
	return nil
}
func matchVersionStrict(ifMatch string, c Clearance) error {
	want := strings.TrimSpace(ifMatch)
	if want == "" || want == "*" {
		return err409("strict clearance version required")
	}
	if want != clearanceETag(c) {
		return err409("clearance version mismatch")
	}
	return nil
}
func limitString(name string, p *string, max int, required bool) error {
	*p = strings.TrimSpace(*p)
	if required && *p == "" {
		return err422(name + " required")
	}
	if len(*p) > max {
		return err422(name + " too long")
	}
	return nil
}

// ---------- webhook worker ----------

type WebhookDispatcher struct {
	store  *BoltStore
	client *http.Client
	log    *slog.Logger
	jobs   chan WebhookDelivery
}

func NewWebhookDispatcher(store *BoltStore, log *slog.Logger, queue int) *WebhookDispatcher {
	if queue <= 0 {
		queue = 2048
	}
	return &WebhookDispatcher{store: store, client: safeClient(), log: log, jobs: make(chan WebhookDelivery, queue)}
}
func (d *WebhookDispatcher) Run(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case del := <-d.jobs:
					d.deliverOnce(ctx, del)
				}
			}
		}()
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			due, err := d.store.ClaimDueDeliveries(ctx, 100)
			if err != nil {
				d.log.Error("claim webhook deliveries failed", "err", err)
				continue
			}
			for _, del := range due {
				select {
				case d.jobs <- del:
				default:
					_ = d.store.MarkDeliveryFailed(context.Background(), del.ID, "webhook worker queue full")
				}
			}
		}
	}
}
func (d *WebhookDispatcher) deliverOnce(ctx context.Context, del WebhookDelivery) {
	var wh WebhookEndpoint
	if err := d.store.View(ctx, func(tx *bolt.Tx) error {
		if !getJSON(tx, bWebhooks, del.WebhookID, &wh) {
			return err404("webhook")
		}
		if !wh.Active {
			return err409("webhook inactive")
		}
		return nil
	}); err != nil {
		_ = d.store.MarkDeliveryDone(context.Background(), del.ID)
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, wh.URL, bytes.NewReader(del.Body))
	if err != nil {
		_ = d.store.MarkDeliveryFailed(context.Background(), del.ID, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Valendir-Event", del.Event)
	req.Header.Set("X-Valendir-Event-ID", del.EventID)
	req.Header.Set("X-Valendir-Delivery", del.ID)
	req.Header.Set("X-Valendir-Signature", "sha256="+hmacHex(wh.Secret, del.Body))
	resp, err := d.client.Do(req)
	if err != nil {
		_ = d.store.MarkDeliveryFailed(context.Background(), del.ID, err.Error())
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = d.store.MarkDeliveryDone(context.Background(), del.ID)
		return
	}
	_ = d.store.MarkDeliveryFailed(context.Background(), del.ID, fmt.Sprintf("status %d", resp.StatusCode))
}

// ---------- background loops ----------

func (a *App) expiryLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = a.store.Update(ctx, func(tx *bolt.Tx) error {
				cur := tx.Bucket(bClearByExpiry).Cursor()
				cutoff := []byte(timeKey(time.Now().UTC()) + "|")
				for k, v := cur.First(); k != nil && bytes.Compare(k, cutoff) <= 0; {
					cid := string(append([]byte(nil), v...))
					if err := cur.Delete(); err != nil {
						return err
					}
					c, err := getClearanceTx(tx, cid)
					if err == nil && !terminalState(c.State) {
						old := c
						c, err = a.svc.machine.Transition(c, StateExpired, time.Now().UTC())
						if err == nil {
							decrementMandateTx(tx, old)
							if err := putClearanceTx(tx, c); err != nil {
								return err
							}
							if err := a.store.appendSystemEventTx(tx, "", c.ID, "system", "AUTO_EXPIRED", EvtExpired, c.ID, clearanceOrgsTx(tx, c), map[string]string{"clearance_id": c.ID}); err != nil {
								return err
							}
						}
					}
					k, v = cur.Next()
				}
				return nil
			})
		}
	}
}
func (a *App) cleanupLoop(ctx context.Context) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = a.store.Update(ctx, func(tx *bolt.Tx) error {
				pruneNonces(tx)
				pruneIdempotency(tx)
				pruneDoneDeliveries(tx, a.cfg.WebhookDoneRetentionDays)
				return nil
			})
			a.checkDBSize("periodic")
		}
	}
}
func pruneNonces(tx *bolt.Tx) {
	cutoff := time.Now().UTC().Add(-nonceTTL).Unix()
	cur := tx.Bucket(bNonces).Cursor()
	count := 0
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		count++
		if len(v) == 8 && int64(binary.BigEndian.Uint64(v)) < cutoff {
			_ = cur.Delete()
		}
	}
	if count <= maxNonceEntries {
		return
	}
	cur = tx.Bucket(bNonces).Cursor()
	removed := 0
	for k, _ := cur.First(); k != nil && removed < count-maxNonceEntries; k, _ = cur.Next() {
		_ = cur.Delete()
		removed++
	}
}
func pruneIdempotency(tx *bolt.Tx) {
	cutoff := timeKey(time.Now().UTC().Add(-idempotencyTTL))
	cur := tx.Bucket(bIdempotencyByTime).Cursor()
	for k, v := cur.First(); k != nil && string(k) < cutoff; k, v = cur.Next() {
		_ = tx.Bucket(bIdempotency).Delete(v)
		_ = cur.Delete()
	}
	if tx.Bucket(bIdempotency).Stats().KeyN <= maxIdempotencyEntries {
		return
	}
	overflow := tx.Bucket(bIdempotency).Stats().KeyN - maxIdempotencyEntries
	cur = tx.Bucket(bIdempotencyByTime).Cursor()
	for k, v := cur.First(); k != nil && overflow > 0; k, v = cur.Next() {
		_ = tx.Bucket(bIdempotency).Delete(v)
		_ = cur.Delete()
		overflow--
	}
}
func pruneDoneDeliveries(tx *bolt.Tx, retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = defaultWebhookDoneRetentionDays
	}
	cutoff := timeKey(time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour))
	cur := tx.Bucket(bDeliveryDone).Cursor()
	for k, v := cur.First(); k != nil && string(k) < cutoff; k, v = cur.Next() {
		_ = tx.Bucket(bDeliveries).Delete(v)
		_ = cur.Delete()
	}
}

// ---------- network safety ----------

func safeClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = safeDial
	return &http.Client{Timeout: 15 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var last error
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
			last = fmt.Errorf("blocked unsafe webhook address %s", ip.IP.String())
			continue
		}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last != nil {
		return nil, last
	}
	return nil, errors.New("no safe webhook address")
}

// ---------- rate limiter ----------

type tokenBucket struct {
	tokens             float64
	lastFill, lastSeen time.Time
}
type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	rate, cap   float64
	lastCleanup time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{buckets: map[string]*tokenBucket{}, rate: float64(perMinute) / 60, cap: math.Max(float64(perMinute)/6, 10), lastCleanup: time.Now()}
}
func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	nowT := time.Now()
	if nowT.Sub(r.lastCleanup) > time.Minute {
		cutoff := nowT.Add(-15 * time.Minute)
		for k, b := range r.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(r.buckets, k)
			}
		}
		r.lastCleanup = nowT
	}
	b := r.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: r.cap, lastFill: nowT, lastSeen: nowT}
		r.buckets[key] = b
	}
	b.tokens = math.Min(r.cap, b.tokens+nowT.Sub(b.lastFill).Seconds()*r.rate)
	b.lastFill = nowT
	b.lastSeen = nowT
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------- main/config ----------

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if cfg.CORS == "*" {
		logger.Warn("CORS wildcard enabled; do not combine with credentials")
	}
	store, err := OpenBoltStore(cfg.DBPath)
	must(err)
	defer store.Close()
	app := &App{cfg: cfg, log: logger, store: store, svc: NewService(store, loadAuthority(logger, cfg.DevMode)), limiter: newRateLimiter(240)}
	app.worker = NewWebhookDispatcher(store, logger, 2048)
	app.checkDBSize("startup")
	must(store.RecoverDeliveries(context.Background()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.worker.Run(ctx, 4)
	go app.expiryLoop(ctx)
	go app.cleanupLoop(ctx)
	srv := &http.Server{Addr: cfg.Addr, Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("valendir-core-v3 listening", "addr", cfg.Addr, "db", cfg.DBPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	logger.Info("shutdown complete")
}
func loadConfig() Config {
	write := env("VALENDIR_ADMIN_WRITE_TOKEN", env("VALENDIR_ADMIN_TOKEN", ""))
	if write == "" {
		write = token()
		fmt.Fprintf(os.Stderr, "generated ephemeral VALENDIR_ADMIN_WRITE_TOKEN fingerprint: %s\n", fingerprint(write))
	}
	read := env("VALENDIR_ADMIN_READ_TOKEN", write)
	emergency := strings.TrimSpace(os.Getenv("VALENDIR_ADMIN_EMERGENCY_TOKEN"))
	if emergency == "" {
		fmt.Fprintln(os.Stderr, "VALENDIR_ADMIN_EMERGENCY_TOKEN is required")
		os.Exit(1)
	}
	if hmac.Equal([]byte(emergency), []byte(write)) {
		fmt.Fprintln(os.Stderr, "VALENDIR_ADMIN_EMERGENCY_TOKEN must be distinct from write token")
		os.Exit(1)
	}
	requireTokenStrength("VALENDIR_ADMIN_WRITE_TOKEN", write)
	requireTokenStrength("VALENDIR_ADMIN_READ_TOKEN", read)
	requireTokenStrength("VALENDIR_ADMIN_EMERGENCY_TOKEN", emergency)
	ttl, _ := strconv.Atoi(env("VALENDIR_CLEARANCE_TTL_DAYS", strconv.Itoa(defaultClearanceTTLDays)))
	if ttl <= 0 {
		ttl = defaultClearanceTTLDays
	}
	maxDBMB, _ := strconv.Atoi(env("VALENDIR_MAX_DB_SIZE_MB", "0"))
	doneRetention, _ := strconv.Atoi(env("VALENDIR_WEBHOOK_DONE_RETENTION_DAYS", strconv.Itoa(defaultWebhookDoneRetentionDays)))
	if doneRetention <= 0 {
		doneRetention = defaultWebhookDoneRetentionDays
	}
	allowedArtifactSchemes = parseCSVSet(env("VALENDIR_ARTIFACT_URI_SCHEMES", "https,ipfs"))
	return Config{Addr: env("VALENDIR_ADDR", ":8080"), DBPath: env("VALENDIR_DB", "valendir.db"), ReadToken: read, WriteToken: write, EmergencyToken: emergency, CORS: strings.TrimSpace(os.Getenv("VALENDIR_CORS_ORIGIN")), TTLDays: ttl, MaxDBSizeBytes: int64(maxDBMB) * 1024 * 1024, WebhookDoneRetentionDays: doneRetention, DevMode: env("VALENDIR_DEV_MODE", "") == "true"}
}
func loadAuthority(log *slog.Logger, devMode bool) ed25519.PrivateKey {
	v := strings.TrimSpace(os.Getenv("VALENDIR_AUTHORITY_KEY"))
	if v == "" {
		if devMode {
			log.Warn("VALENDIR_AUTHORITY_KEY unset; dev mode unsigned attestations enabled")
			return nil
		}
		fmt.Fprintln(os.Stderr, "VALENDIR_AUTHORITY_KEY is required unless VALENDIR_DEV_MODE=true")
		os.Exit(1)
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "VALENDIR_AUTHORITY_KEY must be base64 Ed25519 private key")
		os.Exit(1)
	}
	return ed25519.PrivateKey(raw)
}
func (a *App) checkDBSize(stage string) {
	if a.cfg.MaxDBSizeBytes <= 0 {
		return
	}
	st, err := os.Stat(a.cfg.DBPath)
	if err != nil || st.Size() <= a.cfg.MaxDBSizeBytes {
		return
	}
	if stage == "startup" {
		a.log.Error("database exceeds configured max size", "bytes", st.Size(), "max_bytes", a.cfg.MaxDBSizeBytes)
		os.Exit(1)
	}
	a.log.Warn("database exceeds configured max size", "bytes", st.Size(), "max_bytes", a.cfg.MaxDBSizeBytes)
}

// ---------- small utilities ----------

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func parseCSVSet(v string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out[part] = true
		}
	}
	if len(out) == 0 {
		out["https"] = true
		out["ipfs"] = true
	}
	return out
}
func requireTokenStrength(name, v string) {
	if len(strings.TrimSpace(v)) < minAdminTokenLength {
		fmt.Fprintf(os.Stderr, "%s must be at least %d characters\n", name, minAdminTokenLength)
		os.Exit(1)
	}
}
func now() string                   { return time.Now().UTC().Format(time.RFC3339Nano) }
func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func timeKey(t time.Time) string    { return t.UTC().Format(timeKeyLayout) }
func timeIndexKey(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return timeKey(t)
	}
	return s
}
func deliveryDueKey(nextAttempt, id string) string { return timeIndexKey(nextAttempt) + "|" + id }
func deliveryDoneKey(updatedAt, id string) string  { return timeIndexKey(updatedAt) + "|" + id }
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func randomID(n int) string   { return hex.EncodeToString(randomBytes(n)) }
func id(prefix string) string { return prefix + "_" + randomID(16) }
func token() string           { return base64.RawURLEncoding.EncodeToString(randomBytes(24)) }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hashJSON(v any) string   { return hash(mustJSON(v)) }
func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
func fingerprint(v string) string { return hash([]byte(v))[:16] }
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func pathParts(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
func uniq(in []string, max int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) == max {
			break
		}
	}
	return out
}
func clamp(n, min, max, fallback int) int {
	if n <= 0 {
		return fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
func choose[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
func isMutation(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}
func idempotencyAllowed(method, path string) bool {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	switch {
	case strings.HasPrefix(path, "/v1/admin/backup"):
		return false
	case strings.HasPrefix(path, "/v1/dev/keypair"):
		return false
	case path == "/v1/webhooks":
		return false
	default:
		return true
	}
}
func routeScope(path string) string {
	parts := pathParts(path)
	for i, p := range parts {
		if strings.HasPrefix(p, "clr_") || strings.HasPrefix(p, "agt_") || strings.HasPrefix(p, "mnd_") || strings.HasPrefix(p, "wh_") || strings.HasPrefix(p, "org_") {
			parts[i] = ":id"
		}
	}
	return "/" + strings.Join(parts, "/")
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
func errorCode(msg string) string {
	s := strings.ToUpper(msg)
	repl := strings.NewReplacer(" ", "_", "-", "_", ":", "", ";", "", ".", "", "/", "_", "=", "_", ">", "GT", "<", "LT", "(", "", ")", "", ",", "")
	s = repl.Replace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "ERROR"
	}
	return s
}
