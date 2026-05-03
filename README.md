# Valendir Core

<p align="center">
  <strong>Signed clearance infrastructure for autonomous agents before they create real-world obligations.</strong>
</p>

<p align="center">
  <a href="#why-this-exists">Why</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#clearance-lifecycle">Lifecycle</a> ·
  <a href="#signed-agent-actions">Signed Actions</a> ·
  <a href="#security-posture">Security</a> ·
  <a href="#business-wedge">Use Cases</a>
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white">
  <img alt="Storage" src="https://img.shields.io/badge/storage-bbolt-111827">
  <img alt="Crypto" src="https://img.shields.io/badge/signatures-Ed25519-216CE4">
  <img alt="Posture" src="https://img.shields.io/badge/posture-non--custodial-16A34A">
  <img alt="Status" src="https://img.shields.io/badge/status-single--node--pilot-F59E0B">
</p>

**Valendir is a liability firewall for autonomous AI agents.**

Before an agent accepts a quote, releases an invoice, issues a credit, activates a vendor, or authorizes a claim, Valendir verifies identity, delegated mandate, bilateral proof, dispute state, and release readiness — then emits a signed authorization packet downstream.

> **No downstream release without signed proof of authority.**

## Why this exists

AI agents are starting to make operational decisions with financial, legal, and customer consequences. Existing IAM proves who a user is. Existing payment rails move value. Existing workflow tools route approvals.

Valendir answers the missing question:

> **Was this autonomous action authorized, evidenced, bounded, and safe to release?**

It is the signed clearance layer between autonomous intent and enterprise consequence.


## Status

Valendir Core is an early single-node reference implementation for pilots, demos, and architecture review.

It is intentionally small:

- one Go binary,
- one embedded bbolt database,
- one explicit finite-state machine,
- one signed attestation format,
- one durable webhook outbox.

The goal is not to hide complexity behind a dashboard. The goal is to make agent consequence auditable, replayable, and verifiable.

## What it does

- Runs a durable single-node clearance engine on bbolt.
- Models authorization as an explicit finite-state machine.
- Tracks mandate spend commitments atomically.
- Accepts Ed25519-signed agent actions for `accept`, `release`, and `dispute`.
- Issues Ed25519-signed attestations over canonical clearance bytes.
- Maintains per-clearance tamper-evident audit chains.
- Appends durable business events and delivers them through a webhook outbox.
- Provides idempotent mutation handling and cursor pagination.


## Quickstart

```bash
git clone https://github.com/YOUR_ORG/valendir-core.git
cd valendir-core

go mod tidy

export VALENDIR_DEV_MODE=true
export VALENDIR_ADMIN_WRITE_TOKEN="$(openssl rand -base64 48)"
export VALENDIR_ADMIN_READ_TOKEN="$VALENDIR_ADMIN_WRITE_TOKEN"
export VALENDIR_ADMIN_EMERGENCY_TOKEN="$(openssl rand -base64 48)"

go run .
curl http://localhost:8080/healthz
```

## Clearance lifecycle

```text
PENDING
  -> AGENTS_IDENTIFIED
  -> MANDATE_VERIFIED
  -> PROOF_SUBMITTED
  -> PROOF_VERIFIED
  -> ACCEPTED
  -> RELEASED
```

Exception paths:

```text
PROOF_SUBMITTED / PROOF_VERIFIED / ACCEPTED -> DISPUTED -> RESOLVED
PENDING / ACTIVE STATES -> EXPIRED
```

## Architecture

```text
HTTP API
  -> Service
    -> FSM
      -> BoltStore
        -> Event Log
        -> Audit Chain
        -> Webhook Outbox
          -> Webhook Workers
```

The current implementation is intentionally shipped as a single Go file for artifact portability. A production split would move code into `cmd/`, `internal/domain`, `internal/fsm`, `internal/service`, `internal/store/bolt`, `internal/api`, `internal/webhook`, `internal/crypto`, and `internal/idempotency`.

## Design principles

- **State before side effects** — downstream systems should only act after the clearance state permits release.
- **Proof before approval** — approval is not enough without evidence integrity.
- **Signatures over sessions** — autonomous agents sign scoped actions with Ed25519 keys.
- **Hash-only evidence** — Valendir records proof references and hashes, not sensitive documents.
- **Non-custodial by default** — Valendir authorizes consequence; it does not hold funds.
- **Auditable failure** — disputes, expiries, mismatches, and overrides are first-class states.

## Requirements

- Go 1.22+
- bbolt
- Linux/macOS for local development

Dependencies are tracked in `go.mod`. Run `go mod tidy` after editing module dependencies.

## Configuration

Required for production:

```bash
export VALENDIR_ADMIN_WRITE_TOKEN="32+ chars"
export VALENDIR_ADMIN_READ_TOKEN="32+ chars"
export VALENDIR_ADMIN_EMERGENCY_TOKEN="distinct 32+ chars"
export VALENDIR_AUTHORITY_KEY="base64 Ed25519 private key"
```

Useful optional values:

```bash
export VALENDIR_ADDR=":8080"
export VALENDIR_DB="valendir.db"
export VALENDIR_CLEARANCE_TTL_DAYS="7"
export VALENDIR_WEBHOOK_DONE_RETENTION_DAYS="7"
export VALENDIR_CORS_ORIGIN="https://example.com"
```

Development-only unsigned attestations:

```bash
export VALENDIR_DEV_MODE=true
```

## Core API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `GET` | `/.well-known/valendir-authority.pub` | Authority public key |
| `POST` | `/v1/orgs` | Create organization |
| `POST` | `/v1/agents` | Register Ed25519 agent |
| `POST` | `/v1/mandates` | Create delegated mandate |
| `POST` | `/v1/clearances` | Create clearance |
| `POST` | `/v1/clearances/{id}/identify` | Identify parties |
| `POST` | `/v1/clearances/{id}/verify-mandate` | Verify mandate |
| `POST` | `/v1/clearances/{id}/proofs` | Submit proof bundle |
| `POST` | `/v1/clearances/{id}/verify-proof` | Verify bilateral proof |
| `GET` | `/v1/clearances/{id}/sign-message` | Build signed-action message |
| `POST` | `/v1/clearances/{id}/accept` | Seller signed accept |
| `POST` | `/v1/clearances/{id}/release` | Buyer signed release |
| `POST` | `/v1/clearances/{id}/dispute` | Buyer/seller signed dispute |
| `POST` | `/v1/clearances/{id}/attestation` | Issue signed attestation |
| `GET` | `/v1/audit?clearance_id={id}` | Read audit chain |
| `GET` | `/v1/audit/verify?clearance_id={id}` | Verify audit chain |
| `GET` | `/v1/events` | Read event log |
| `POST` | `/v1/webhooks` | Register webhook endpoint |
| `GET` | `/v1/metrics` | Prometheus-style metrics |

Admin routes require bearer auth. Mutating clearance routes should use `If-Match` where strict versioning is required.

## Signed agent actions

Agents sign:

```text
valendir/v3
{action}
{clearance_id}
{agent_id}
{clearance_etag}
{nonce}
{timestamp}
```

Supported actions:

- `accept` — seller agent
- `release` — buyer agent
- `dispute` — buyer or seller agent

Valendir checks timestamp skew, nonce replay, active agent status, role authorization, and Ed25519 signature validity.

## Security posture

- Non-custodial: Valendir does not hold funds.
- Hash-only proof model: raw documents stay in customer systems.
- Strict JSON decoding and request-size limits.
- Ed25519 signed agent actions and attestations.
- HMAC-signed webhook deliveries.
- Safe webhook dialer blocks loopback, private, link-local, and multicast targets.
- Tamper-evident audit chains per clearance.
- Idempotency for supported mutations.
- Cursor pagination for list endpoints.

### Threat model covered

Valendir is designed to reduce:

- agent overreach beyond delegated mandate,
- replayed authorization actions,
- unsigned downstream releases,
- proof/receipt mismatch,
- stale mandate usage,
- webhook delivery loss,
- audit trail tampering,
- accidental release during dispute.

Valendir does **not** replace ERP controls, payment authorization, secrets management, legal review, or production HA infrastructure.

## What Valendir is not

Valendir is not:

- an agent framework,
- a payment rail,
- an ERP,
- a document store,
- a legal contract engine,
- a custody provider.

It is the signed clearance layer between autonomous intent and enterprise consequence.

## Deployment posture

This build is suitable for local development, demos, and single-node pilots. For high-availability production, extract storage behind an interface and move from embedded bbolt to a replicated database or consensus-backed store.

## Business wedge

Start with one workflow where an AI agent can create real liability:

- quote acceptance,
- invoice release readiness,
- support credit authorization,
- vendor activation,
- claims repair authorization,
- buyer-supplier agent negotiation.

The product promise:

> No downstream release without signed proof of authority.

## Ideal first pilot

The best first Valendir deployment is narrow:

```text
one workflow
one transaction type
one buyer persona
one downstream system
one release event
one measurable liability boundary
```

Examples:

- AI procurement agent can accept MRO quotes up to $50k.
- Support agent can issue account credits under policy.
- AP agent can mark invoices release-ready after receipt proof.
- Claims agent can authorize repairs after inspection evidence.


## License

License TBD. Do not use in production without reviewing operational, security, and legal requirements.
