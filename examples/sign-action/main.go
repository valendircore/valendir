package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type signedReq struct {
	AgentID       string `json:"agent_id"`
	ClearanceETag string `json:"clearance_etag"`
	Nonce         string `json:"nonce"`
	Timestamp     int64  `json:"timestamp"`
	SignatureB64  string `json:"signature_b64"`
}

func main() {
	privB64 := env("PRIVATE_KEY_B64")
	action := strings.ToLower(env("ACTION"))
	clearanceID := env("CLEARANCE_ID")
	agentID := env("AGENT_ID")
	clearanceETag := env("CLEARANCE_ETAG")
	nonce := env("NONCE")
	ts := env("TIMESTAMP")

	if action != "accept" && action != "release" && action != "dispute" {
		log.Fatal("ACTION must be one of: accept, release, dispute")
	}

	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		log.Fatalf("invalid TIMESTAMP: %v", err)
	}

	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		log.Fatalf("invalid PRIVATE_KEY_B64: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		log.Fatalf("private key must be %d bytes", ed25519.PrivateKeySize)
	}

	msg := signingMessage(action, clearanceID, agentID, clearanceETag, nonce, tsInt)
	sig := ed25519.Sign(ed25519.PrivateKey(priv), msg)

	out := signedReq{
		AgentID:       agentID,
		ClearanceETag: clearanceETag,
		Nonce:         nonce,
		Timestamp:     tsInt,
		SignatureB64:  base64.StdEncoding.EncodeToString(sig),
	}

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		log.Fatal(err)
	}
}

func env(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("required env: %s", k)
	}
	return v
}

func signingMessage(action, clearanceID, agentID, clearanceETag, nonce string, ts int64) []byte {
	return []byte(fmt.Sprintf(
		"valendir/v3\n%s\n%s\n%s\n%s\n%s\n%d",
		action,
		clearanceID,
		agentID,
		clearanceETag,
		nonce,
		ts,
	))
}
