// Package ecdsa provides threshold ECDSA signing using the GG20 protocol.
// This package wraps bnb-chain/tss-lib with a session-based API.
package ecdsa

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

// ECDSAKeyShare holds a participant's share of the threshold ECDSA key.
type ECDSAKeyShare struct {
	PartyID      string                      `json:"party_id"`
	SaveData     *keygen.LocalPartySaveData  `json:"save_data"`
	Threshold    int                         `json:"threshold"`
	TotalParties int                         `json:"total_parties"`
}

// ECDSASignature is an Ethereum-compatible ECDSA signature.
type ECDSASignature struct {
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
	V uint8    `json:"v"` // Recovery ID (27 or 28 for Ethereum)
}

// DKGRound1Message contains data broadcast in DKG round 1.
type DKGRound1Message struct {
	FromPartyID string `json:"from_party_id"`
	IsBroadcast bool   `json:"is_broadcast"`
	MsgBytes    []byte `json:"msg_bytes"`
}

// DKGRound2Message1 contains P2P data sent in DKG round 2.
type DKGRound2Message1 struct {
	FromPartyID string `json:"from_party_id"`
	ToPartyID   string `json:"to_party_id"`
	MsgBytes    []byte `json:"msg_bytes"`
}

// DKGRound2Message2 contains broadcast data in DKG round 2.
type DKGRound2Message2 struct {
	FromPartyID string `json:"from_party_id"`
	IsBroadcast bool   `json:"is_broadcast"`
	MsgBytes    []byte `json:"msg_bytes"`
}

// DKGRound3Message contains data broadcast in DKG round 3.
type DKGRound3Message struct {
	FromPartyID string `json:"from_party_id"`
	IsBroadcast bool   `json:"is_broadcast"`
	MsgBytes    []byte `json:"msg_bytes"`
}

// SigningRoundMessage contains data for a signing round.
type SigningRoundMessage struct {
	FromPartyID string `json:"from_party_id"`
	ToPartyID   string `json:"to_party_id"` // Empty string = broadcast
	Round       int    `json:"round"`
	MsgBytes    []byte `json:"msg_bytes"`
}
