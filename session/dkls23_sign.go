package session

import (
	"errors"
	"sync"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/sign"
)

// DKLS23SigningSession manages a single DKLS23 signing operation.
// Each session produces one signature for one message.
//
// All phase methods are safe for concurrent use; a mutex serializes access
// to mutable state (phase counter, intermediate kept values, compressedR).
//
// Create sessions using [NewDKLS23SigningSession].
type DKLS23SigningSession struct {
	mu sync.Mutex

	party          *sign.Party
	signData       *sign.SignData
	counterparties []uint8

	// Phase state
	phase       int
	uniqueKeep1 *sign.UniqueKeep1to2
	keep1       map[uint8]*sign.Phase1ToPhase2Keep
	uniqueKeep2 *sign.UniqueKeep2to3
	keep2       map[uint8]*sign.Phase2ToPhase3Keep
	compressedR []byte
}

// DKLS23SignPhase1Output contains all data generated during signing phase 1.
type DKLS23SignPhase1Output struct {
	// Messages maps recipient counterparty index to their message.
	// Send Messages[j] to counterparty j.
	Messages map[uint8]*sign.Phase1ToPhase2Transmit
}

// DKLS23SignPhase2Output contains all data generated during signing phase 2.
type DKLS23SignPhase2Output struct {
	// Messages maps recipient counterparty index to their message.
	// Send Messages[j] to counterparty j.
	Messages map[uint8]*sign.Phase2ToPhase3Transmit
}

// DKLS23SignPhase3Output contains all data generated during signing phase 3.
type DKLS23SignPhase3Output struct {
	// Broadcast is sent to all counterparties.
	Broadcast *sign.Phase3Broadcast
}

// NewDKLS23SigningSession creates a new signing session for the given message.
//
// Parameters:
//   - party: The signing party from DKG
//   - messageHash: 32-byte hash of the message to sign
//   - signID: Unique identifier for this signing session
//   - counterparties: The other party indices participating in this signing
//     (must be exactly threshold-1 other parties)
func NewDKLS23SigningSession(
	party *sign.Party,
	messageHash [32]byte,
	signID []byte,
	counterparties []uint8,
) (*DKLS23SigningSession, error) {
	if party == nil {
		return nil, errors.New("party cannot be nil")
	}
	if len(signID) == 0 {
		return nil, errors.New("signID cannot be empty")
	}

	expectedCounterparties := int(party.Threshold - 1)
	if len(counterparties) != expectedCounterparties {
		return nil, errors.New("wrong number of counterparties for threshold")
	}

	// Verify counterparties are valid
	for _, cp := range counterparties {
		if cp < 1 || cp > party.Total {
			return nil, errors.New("invalid counterparty index")
		}
		if cp == party.Index {
			return nil, errors.New("counterparties cannot include self")
		}
	}

	// Check for duplicate counterparties
	cpSet := make(map[uint8]bool, len(counterparties))
	for _, cp := range counterparties {
		if cpSet[cp] {
			return nil, errors.New("duplicate counterparty index")
		}
		cpSet[cp] = true
	}

	// Copy inputs to prevent external modification
	sidCopy := make([]byte, len(signID))
	copy(sidCopy, signID)

	cpCopy := make([]uint8, len(counterparties))
	copy(cpCopy, counterparties)

	return &DKLS23SigningSession{
		party: party,
		signData: &sign.SignData{
			SignID:         sidCopy,
			Counterparties: cpCopy,
			MessageHash:    messageHash,
		},
		counterparties: cpCopy,
		phase:          0,
	}, nil
}

// Phase1 executes signing phase 1: generate instance key and start MtA.
func (s *DKLS23SigningSession) Phase1() (*DKLS23SignPhase1Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != 0 {
		return nil, errors.New("signing phase 1 already completed")
	}

	uniqueKeep, keep, transmit, err := s.party.Phase1(s.signData)
	if err != nil {
		return nil, err
	}

	s.uniqueKeep1 = uniqueKeep
	s.keep1 = keep
	s.phase = 1

	// Convert transmit slice to map for easier routing
	messages := make(map[uint8]*sign.Phase1ToPhase2Transmit)
	for _, msg := range transmit {
		messages[msg.Receiver] = msg
	}

	return &DKLS23SignPhase1Output{
		Messages: messages,
	}, nil
}

// Phase2 executes signing phase 2: continue MtA protocol.
//
// Parameters:
//   - received: Messages received from counterparties in phase 1.
//     Map from sender index to their message.
func (s *DKLS23SigningSession) Phase2(received map[uint8]*sign.Phase1ToPhase2Transmit) (*DKLS23SignPhase2Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != 1 {
		return nil, errors.New("must complete signing phase 1 before phase 2")
	}

	// Convert map to slice
	receivedSlice := make([]*sign.Phase1ToPhase2Transmit, 0, len(received))
	for _, cp := range s.counterparties {
		msg, ok := received[cp]
		if !ok {
			return nil, errors.New("missing phase 1 message from counterparty")
		}
		receivedSlice = append(receivedSlice, msg)
	}

	uniqueKeep, keep, transmit, err := s.party.Phase2(s.signData, s.uniqueKeep1, s.keep1, receivedSlice)
	if err != nil {
		return nil, err
	}

	s.uniqueKeep2 = uniqueKeep
	s.keep2 = keep
	s.phase = 2

	// Clear references to phase 1 state (no longer needed).
	// Note: scalar values in these structs are shared by pointer with
	// uniqueKeep2/keep2, so we must NOT zero them here. They will be
	// zeroed when Phase3 consumes and defers cleanup of Phase2ToPhase3Keep
	// and UniqueKeep2to3 (see sign/protocol.go Phase3).
	s.uniqueKeep1 = nil
	s.keep1 = nil

	// Convert transmit slice to map for easier routing
	messages := make(map[uint8]*sign.Phase2ToPhase3Transmit)
	for _, msg := range transmit {
		messages[msg.Receiver] = msg
	}

	return &DKLS23SignPhase2Output{
		Messages: messages,
	}, nil
}

// Phase3 executes signing phase 3: verify and compute signature shares.
//
// Parameters:
//   - received: Messages received from counterparties in phase 2.
//     Map from sender index to their message.
func (s *DKLS23SigningSession) Phase3(received map[uint8]*sign.Phase2ToPhase3Transmit) (*DKLS23SignPhase3Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != 2 {
		return nil, errors.New("must complete signing phase 2 before phase 3")
	}

	// Convert map to slice
	receivedSlice := make([]*sign.Phase2ToPhase3Transmit, 0, len(received))
	for _, cp := range s.counterparties {
		msg, ok := received[cp]
		if !ok {
			return nil, errors.New("missing phase 2 message from counterparty")
		}
		receivedSlice = append(receivedSlice, msg)
	}

	compressedR, broadcast, err := s.party.Phase3(s.signData, s.uniqueKeep2, s.keep2, receivedSlice)
	if err != nil {
		return nil, err
	}

	s.compressedR = compressedR
	s.phase = 3

	// Clear references to phase 2 state (no longer needed).
	// Secret scalars in uniqueKeep2 and keep2 were already zeroed by
	// sign.Party.Phase3's deferred cleanup (UniqueKeep2to3.Zero and
	// Phase2ToPhase3Keep.Zero).
	s.uniqueKeep2 = nil
	s.keep2 = nil

	return &DKLS23SignPhase3Output{
		Broadcast: broadcast,
	}, nil
}

// Phase4 executes signing phase 4: aggregate and finalize signature.
//
// Parameters:
//   - received: Broadcasts received from all parties (including self).
//   - normalize: If true, normalize S to low form for Bitcoin/Ethereum compatibility.
func (s *DKLS23SigningSession) Phase4(received []*sign.Phase3Broadcast, normalize bool) (*sign.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != 3 {
		return nil, errors.New("must complete signing phase 3 before phase 4")
	}

	sig, err := s.party.Phase4(s.signData, s.compressedR, received, normalize)
	if err != nil {
		return nil, err
	}

	s.phase = 4

	// Clear remaining state to release references to secret material.
	// The Party is externally owned and not zeroed here, but the session's
	// reference is released so the session itself does not pin it.
	s.compressedR = nil
	s.signData = nil
	s.party = nil

	return sig, nil
}

// Phase returns the current phase number (0-4).
func (s *DKLS23SigningSession) Phase() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// DKLS23QuickSign performs a complete signing operation when all parties are local.
//
// This is useful for testing or single-machine threshold setups where all
// participants are in the same process. For distributed signing, use
// [DKLS23SigningSession] instead.
func DKLS23QuickSign(
	parties []*sign.Party,
	messageHash [32]byte,
	signID []byte,
	normalize bool,
) (*sign.Signature, error) {
	if len(parties) == 0 {
		return nil, errors.New("no parties provided")
	}

	threshold := parties[0].Threshold
	if len(parties) != int(threshold) {
		return nil, errors.New("number of parties must equal threshold")
	}

	// Build counterparties lists for each party
	allIndices := make([]uint8, len(parties))
	for i, p := range parties {
		allIndices[i] = p.Index
	}

	// Create signing sessions
	sessions := make([]*DKLS23SigningSession, len(parties))
	for i, p := range parties {
		counterparties := make([]uint8, 0, len(parties)-1)
		for _, idx := range allIndices {
			if idx != p.Index {
				counterparties = append(counterparties, idx)
			}
		}

		var err error
		sessions[i], err = NewDKLS23SigningSession(p, messageHash, signID, counterparties)
		if err != nil {
			return nil, err
		}
	}

	// Phase 1
	phase1Outputs := make([]*DKLS23SignPhase1Output, len(sessions))
	for i, sess := range sessions {
		var err error
		phase1Outputs[i], err = sess.Phase1()
		if err != nil {
			return nil, err
		}
	}

	// Collect phase 1 messages by receiver
	phase1ByReceiver := make(map[uint8]map[uint8]*sign.Phase1ToPhase2Transmit)
	for i, output := range phase1Outputs {
		for receiver, msg := range output.Messages {
			if phase1ByReceiver[receiver] == nil {
				phase1ByReceiver[receiver] = make(map[uint8]*sign.Phase1ToPhase2Transmit)
			}
			phase1ByReceiver[receiver][parties[i].Index] = msg
		}
	}

	// Phase 2
	phase2Outputs := make([]*DKLS23SignPhase2Output, len(sessions))
	for i, sess := range sessions {
		received := phase1ByReceiver[parties[i].Index]
		var err error
		phase2Outputs[i], err = sess.Phase2(received)
		if err != nil {
			return nil, err
		}
	}

	// Collect phase 2 messages by receiver
	phase2ByReceiver := make(map[uint8]map[uint8]*sign.Phase2ToPhase3Transmit)
	for i, output := range phase2Outputs {
		for receiver, msg := range output.Messages {
			if phase2ByReceiver[receiver] == nil {
				phase2ByReceiver[receiver] = make(map[uint8]*sign.Phase2ToPhase3Transmit)
			}
			phase2ByReceiver[receiver][parties[i].Index] = msg
		}
	}

	// Phase 3
	phase3Outputs := make([]*DKLS23SignPhase3Output, len(sessions))
	for i, sess := range sessions {
		received := phase2ByReceiver[parties[i].Index]
		var err error
		phase3Outputs[i], err = sess.Phase3(received)
		if err != nil {
			return nil, err
		}
	}

	// Collect all broadcasts
	broadcasts := make([]*sign.Phase3Broadcast, len(phase3Outputs))
	for i, output := range phase3Outputs {
		broadcasts[i] = output.Broadcast
	}

	// Phase4 is called only on sessions[0] since any party can finalize.
	// Other sessions' compressedR values (public nonce points) are not zeroed
	// as they are not secret material.
	return sessions[0].Phase4(broadcasts, normalize)
}

// DKLS23MessageHash creates a message hash from arbitrary data using Keccak256.
// This is a convenience function for Ethereum-style message hashing.
func DKLS23MessageHash(data []byte) dkls23.HashOutput {
	return dkls23.Hash(data, nil)
}
