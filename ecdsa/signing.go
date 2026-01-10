package ecdsa

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// SigningRoundTimeout is the timeout for collecting messages from a single round.
// This is for the internal tss-lib channel operations, not network timeouts.
var SigningRoundTimeout = 10 * time.Second

// SigningSession manages a single threshold ECDSA signing operation.
// GG20 signing has up to 9 rounds.
type SigningSession struct {
	mu sync.Mutex

	partyID    *tss.PartyID
	params     *tss.Parameters
	party      tss.Party
	allParties tss.SortedPartyIDs
	keyShare   *ECDSAKeyShare
	message    *big.Int // Message hash to sign (32 bytes)

	// Channel-based internals
	outCh chan tss.Message
	endCh chan *common.SignatureData
	errCh chan *tss.Error

	// Round tracking (GG20 has up to 9 rounds)
	currentRound int
	maxRounds    int

	// Final result
	signature *ECDSASignature
	completed bool
}

// NewSigningSession creates a signing session for the given message.
// signerPartyIDs: list of party IDs participating (must be >= threshold)
// keyShare: the local party's key share from DKG
// messageHash: 32-byte hash to sign (e.g., Ethereum tx hash)
func NewSigningSession(
	signerPartyIDs []string,
	keyShare *ECDSAKeyShare,
	messageHash []byte,
) (*SigningSession, error) {
	if len(messageHash) != 32 {
		return nil, fmt.Errorf("message hash must be 32 bytes, got %d", len(messageHash))
	}
	if len(signerPartyIDs) < keyShare.Threshold {
		return nil, fmt.Errorf("need at least %d signers, got %d", keyShare.Threshold, len(signerPartyIDs))
	}

	// Convert message to big.Int
	msgBigInt := new(big.Int).SetBytes(messageHash)

	// Create party IDs for signers
	partyIDs := make([]*tss.PartyID, len(signerPartyIDs))
	var ourPartyID *tss.PartyID

	for i, pid := range signerPartyIDs {
		// Create party ID from string
		id, err := IntFromPartyID(pid)
		if err != nil {
			return nil, fmt.Errorf("invalid party ID %s: %w", pid, err)
		}
		partyIDs[i] = tss.NewPartyID(pid, fmt.Sprintf("Party %d", id), big.NewInt(int64(id)))
		if pid == keyShare.PartyID {
			ourPartyID = partyIDs[i]
		}
	}

	if ourPartyID == nil {
		return nil, fmt.Errorf("our party ID %s not found in signer list", keyShare.PartyID)
	}

	// Sort party IDs
	sortedIDs := tss.SortPartyIDs(partyIDs)

	// Create parameters
	// tss-lib uses threshold = t where t+1 signers are needed
	// keyShare.Threshold is ALREADY in tss-lib format (t, not t+1) because
	// it was stored from params.Threshold() during DKG
	ctx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.S256(), ctx, ourPartyID, len(signerPartyIDs), keyShare.Threshold)

	fmt.Printf("[ECDSA-DEBUG] NewSigningSession: ourPartyID=%s, numSigners=%d, threshold=%d, keyShare.PartyID=%s\n",
		ourPartyID.Id, len(signerPartyIDs), keyShare.Threshold, keyShare.PartyID)
	for i, pid := range sortedIDs {
		fmt.Printf("[ECDSA-DEBUG]   sortedID[%d]: %s (key=%s)\n", i, pid.Id, pid.KeyInt().String())
	}

	return &SigningSession{
		partyID:      ourPartyID,
		params:       params,
		allParties:   sortedIDs,
		keyShare:     keyShare,
		message:      msgBigInt,
		currentRound: 0,
		maxRounds:    9,
		outCh:        make(chan tss.Message, 100),
		endCh:        make(chan *common.SignatureData, 1),
		errCh:        make(chan *tss.Error, 1),
	}, nil
}

// Start begins the signing protocol and returns Round 1 messages.
func (s *SigningSession) Start() ([]*SigningRoundMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentRound != 0 {
		return nil, fmt.Errorf("signing already started")
	}

	// Create local party
	s.party = signing.NewLocalParty(s.message, s.params, *s.keyShare.SaveData, s.outCh, s.endCh)

	// Start in background
	go func() {
		if err := s.party.Start(); err != nil {
			s.errCh <- err
		}
	}()

	s.currentRound = 1

	return s.collectRoundMessages(1)
}

// collectRoundMessages collects messages from outCh for the given round.
func (s *SigningSession) collectRoundMessages(round int) ([]*SigningRoundMessage, error) {
	var messages []*SigningRoundMessage

	fmt.Printf("[ECDSA-DEBUG] collectRoundMessages: waiting for round %d output (timeout=%v)\n", round, SigningRoundTimeout)

	// Collect messages with timeout
	timeout := time.After(SigningRoundTimeout)

	for {
		select {
		case msg := <-s.outCh:
			fmt.Printf("[ECDSA-DEBUG] collectRoundMessages: got message on outCh\n")
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				return nil, fmt.Errorf("serializing message: %w", err)
			}

			if routing.IsBroadcast {
				messages = append(messages, &SigningRoundMessage{
					FromPartyID: s.partyID.Id,
					ToPartyID:   "", // Empty = broadcast
					Round:       round,
					MsgBytes:    msgBytes,
				})
				// Broadcast means we're done
				return messages, nil
			} else {
				// P2P messages
				for _, to := range routing.To {
					messages = append(messages, &SigningRoundMessage{
						FromPartyID: s.partyID.Id,
						ToPartyID:   to.Id,
						Round:       round,
						MsgBytes:    msgBytes,
					})
				}
			}

		case result := <-s.endCh:
			fmt.Printf("[ECDSA-DEBUG] collectRoundMessages: signing complete!\n")
			s.completed = true
			s.signature = convertToECDSASignature(result)
			return messages, nil

		case err := <-s.errCh:
			fmt.Printf("[ECDSA-DEBUG] collectRoundMessages: got error from errCh: %v\n", err.Cause())
			return nil, fmt.Errorf("signing error in round %d: %w", round, err.Cause())

		case <-timeout:
			fmt.Printf("[ECDSA-DEBUG] collectRoundMessages: timeout, returning %d messages\n", len(messages))
			// Return what we have
			return messages, nil
		}
	}
}

// findPartyID finds a party ID by its string identifier.
func (s *SigningSession) findPartyID(id string) *tss.PartyID {
	for _, party := range s.allParties {
		if party.Id == id {
			return party
		}
	}
	return nil
}

// ProcessRound processes incoming messages and returns next round messages.
// Returns nil messages when signing is complete.
func (s *SigningSession) ProcessRound(messages []*SigningRoundMessage) ([]*SigningRoundMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.completed {
		return nil, nil
	}

	fmt.Printf("[ECDSA-DEBUG] ProcessRound: received %d messages, currentRound=%d\n", len(messages), s.currentRound)

	// Update party with received messages
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		if msg.FromPartyID == s.partyID.Id {
			fmt.Printf("[ECDSA-DEBUG]   Skipping own message from %s\n", msg.FromPartyID)
			continue // Skip our own messages
		}

		// Check if message is for us
		if msg.ToPartyID != "" && msg.ToPartyID != s.partyID.Id {
			fmt.Printf("[ECDSA-DEBUG]   Skipping P2P message not for us: from=%s, to=%s\n", msg.FromPartyID, msg.ToPartyID)
			continue // P2P message not for us
		}

		// Find the sender's party ID from our sorted list
		fromParty := s.findPartyID(msg.FromPartyID)
		if fromParty == nil {
			return nil, fmt.Errorf("unknown sender party: %s", msg.FromPartyID)
		}

		isBroadcast := msg.ToPartyID == ""
		fmt.Printf("[ECDSA-DEBUG]   Processing message from %s, round=%d, broadcast=%v, msgLen=%d\n",
			msg.FromPartyID, msg.Round, isBroadcast, len(msg.MsgBytes))

		parsedMsg, parseErr := tss.ParseWireMessage(msg.MsgBytes, fromParty, isBroadcast)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing message from %s: %w", msg.FromPartyID, parseErr)
		}

		ok, tssErr := s.party.Update(parsedMsg)
		if tssErr != nil {
			return nil, fmt.Errorf("updating party with message from %s: %v (cause: %v)", msg.FromPartyID, tssErr, tssErr.Cause())
		}
		if !ok {
			fmt.Printf("[ECDSA-DEBUG]   Update returned false for message from %s (may be duplicate)\n", msg.FromPartyID)
		} else {
			fmt.Printf("[ECDSA-DEBUG]   Update succeeded for message from %s\n", msg.FromPartyID)
		}

		// Check for any errors produced during update
		select {
		case err := <-s.errCh:
			fmt.Printf("[ECDSA-DEBUG]   Error after update: %v\n", err.Cause())
			return nil, fmt.Errorf("error after update from %s: %v", msg.FromPartyID, err.Cause())
		default:
		}
	}

	// Give tss-lib a moment to produce output after processing all messages
	time.Sleep(500 * time.Millisecond)

	// Check for any pending output before incrementing round
	select {
	case msg := <-s.outCh:
		fmt.Printf("[ECDSA-DEBUG] Got pending output message after processing\n")
		msgBytes, routing, err := msg.WireBytes()
		if err == nil {
			// Put it back for collectRoundMessages to find
			go func() { s.outCh <- msg }()
			_ = msgBytes
			_ = routing
		}
	case err := <-s.errCh:
		fmt.Printf("[ECDSA-DEBUG] Got error after processing: %v\n", err.Cause())
		return nil, fmt.Errorf("error after processing: %v", err.Cause())
	case result := <-s.endCh:
		fmt.Printf("[ECDSA-DEBUG] Signing complete after processing!\n")
		s.completed = true
		s.signature = convertToECDSASignature(result)
		return nil, nil
	default:
		fmt.Printf("[ECDSA-DEBUG] No pending output after processing\n")
	}

	// Check for completion with a brief wait
	// (result may be produced shortly after processing the last message)
	select {
	case result := <-s.endCh:
		s.completed = true
		s.signature = convertToECDSASignature(result)
		return nil, nil

	case err := <-s.errCh:
		return nil, fmt.Errorf("signing error: %w", err.Cause())

	case <-time.After(100 * time.Millisecond):
		// Give some time for async completion
	}

	// Check again after brief wait
	select {
	case result := <-s.endCh:
		s.completed = true
		s.signature = convertToECDSASignature(result)
		return nil, nil
	default:
	}

	s.currentRound++
	if s.currentRound > s.maxRounds {
		// If we've exceeded max rounds, wait a bit longer for completion
		select {
		case result := <-s.endCh:
			s.completed = true
			s.signature = convertToECDSASignature(result)
			return nil, nil
		case err := <-s.errCh:
			return nil, fmt.Errorf("signing error: %w", err.Cause())
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("signing timeout: exceeded maximum rounds (%d)", s.maxRounds)
		}
	}

	return s.collectRoundMessages(s.currentRound)
}

// IsComplete returns true if signing finished.
func (s *SigningSession) IsComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completed
}

// WaitForCompletion blocks until signing completes or timeout.
func (s *SigningSession) WaitForCompletion(timeout time.Duration) error {
	s.mu.Lock()
	if s.completed {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	select {
	case result := <-s.endCh:
		s.mu.Lock()
		s.completed = true
		s.signature = convertToECDSASignature(result)
		s.mu.Unlock()
		return nil

	case err := <-s.errCh:
		if err != nil && err.Cause() != nil {
			return fmt.Errorf("signing error: %w", err.Cause())
		}
		return fmt.Errorf("signing failed with unknown error")

	case <-time.After(timeout):
		return fmt.Errorf("signing timeout after %v", timeout)
	}
}

// GetSignature returns the final signature (only valid after IsComplete).
func (s *SigningSession) GetSignature() (*ECDSASignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.completed {
		return nil, fmt.Errorf("signing not complete")
	}
	return s.signature, nil
}

// CurrentRound returns the current round number (1-9).
func (s *SigningSession) CurrentRound() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentRound
}

// PartyID returns the session's party ID.
func (s *SigningSession) PartyID() string {
	return s.partyID.Id
}

// convertToECDSASignature converts tss-lib signature to our format.
func convertToECDSASignature(data *common.SignatureData) *ECDSASignature {
	r := new(big.Int).SetBytes(data.R)
	sVal := new(big.Int).SetBytes(data.S)

	// Recovery ID for Ethereum
	v := uint8(27)
	if len(data.SignatureRecovery) > 0 {
		v = uint8(data.SignatureRecovery[0]) + 27
	}

	return &ECDSASignature{
		R: r,
		S: sVal,
		V: v,
	}
}
