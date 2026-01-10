package ecdsa

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// DKGRoundTimeout is the timeout for collecting messages from a single DKG round.
// This is for the internal tss-lib channel operations, not network timeouts.
var DKGRoundTimeout = 10 * time.Second

// DKGParticipant manages the distributed key generation with a session-based API.
// It wraps tss-lib's channel-based internals.
type DKGParticipant struct {
	mu sync.Mutex

	partyID    *tss.PartyID
	params     *tss.Parameters
	party      tss.Party
	allParties tss.SortedPartyIDs

	// Channel-based internals (hidden from user)
	outCh chan tss.Message
	endCh chan *keygen.LocalPartySaveData
	errCh chan *tss.Error

	// Round tracking
	currentRound int
	pendingMsgs  []tss.Message // Messages waiting to be sent

	// Final result
	result    *keygen.LocalPartySaveData
	completed bool

	// Pre-params (Paillier keys, etc.)
	preParams *keygen.LocalPreParams
}

// NewDKGParticipant creates a new DKG participant.
// id: 1-indexed participant ID
// threshold: minimum signers needed (e.g., 2 for 2-of-3)
// totalParties: n total participants
func NewDKGParticipant(id, threshold, totalParties int) (*DKGParticipant, error) {
	if id < 1 || id > totalParties {
		return nil, fmt.Errorf("id must be in range [1, %d]", totalParties)
	}
	if threshold < 1 || threshold > totalParties {
		return nil, fmt.Errorf("threshold must be in [1, %d]", totalParties)
	}

	// Create party IDs for all participants
	partyIDs := make([]*tss.PartyID, totalParties)
	for i := 1; i <= totalParties; i++ {
		key := big.NewInt(int64(i))
		partyIDs[i-1] = tss.NewPartyID(
			fmt.Sprintf("party-%d", i),
			fmt.Sprintf("Party %d", i),
			key,
		)
	}

	// Our party ID
	ourPartyID := partyIDs[id-1]

	// Sort party IDs (required by tss-lib)
	sortedIDs := tss.SortPartyIDs(partyIDs)

	// Create parameters
	// tss-lib uses threshold = t where t+1 signers are needed
	// We use threshold = number of signers needed, so subtract 1
	ctx := tss.NewPeerContext(sortedIDs)
	tssThreshold := threshold - 1
	params := tss.NewParameters(tss.S256(), ctx, ourPartyID, totalParties, tssThreshold)

	return &DKGParticipant{
		partyID:      ourPartyID,
		params:       params,
		allParties:   sortedIDs,
		currentRound: 0,
		outCh:        make(chan tss.Message, 100),
		endCh:        make(chan *keygen.LocalPartySaveData, 1),
		errCh:        make(chan *tss.Error, 1),
	}, nil
}

// GeneratePreParams generates the expensive Paillier keys.
// Call this before Start() to pre-generate. If not called, Start() will generate them.
func (p *DKGParticipant) GeneratePreParams(timeout time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.preParams != nil {
		return nil // Already generated
	}

	preParams, err := keygen.GeneratePreParams(timeout)
	if err != nil {
		return fmt.Errorf("generating pre-params: %w", err)
	}
	p.preParams = preParams
	return nil
}

// Start begins the DKG protocol and returns Round 1 messages.
func (p *DKGParticipant) Start() ([]*DKGRound1Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentRound != 0 {
		return nil, fmt.Errorf("DKG already started")
	}

	// Generate pre-params if not already done
	if p.preParams == nil {
		preParams, err := keygen.GeneratePreParams(3 * time.Minute)
		if err != nil {
			return nil, fmt.Errorf("generating pre-params: %w", err)
		}
		p.preParams = preParams
	}

	// Create local party
	p.party = keygen.NewLocalParty(p.params, p.outCh, p.endCh, *p.preParams)

	// Start the party in background
	go func() {
		if err := p.party.Start(); err != nil {
			p.errCh <- err
		}
	}()

	p.currentRound = 1

	// Collect Round 1 messages from outCh
	return p.collectRound1Messages()
}

// collectRound1Messages collects messages from outCh for round 1.
func (p *DKGParticipant) collectRound1Messages() ([]*DKGRound1Message, error) {
	var messages []*DKGRound1Message

	// Collect messages with timeout
	timeout := time.After(DKGRoundTimeout)
	expectedMsgs := len(p.allParties) - 1 // Broadcast to all others

	for len(messages) < expectedMsgs {
		select {
		case msg := <-p.outCh:
			// Check if this is a round 1 message
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				return nil, fmt.Errorf("serializing message: %w", err)
			}

			messages = append(messages, &DKGRound1Message{
				FromPartyID: p.partyID.Id,
				IsBroadcast: routing.IsBroadcast,
				MsgBytes:    msgBytes,
			})

			// For broadcast messages, we only get one
			if routing.IsBroadcast {
				return messages, nil
			}

		case err := <-p.errCh:
			return nil, fmt.Errorf("DKG error: %w", err.Cause())

		case <-timeout:
			if len(messages) > 0 {
				return messages, nil
			}
			return nil, fmt.Errorf("timeout waiting for round 1 messages")
		}
	}

	return messages, nil
}

// ProcessRound1 handles incoming Round 1 messages and produces Round 2 messages.
func (p *DKGParticipant) ProcessRound1(messages []*DKGRound1Message) ([]*DKGRound2Message1, []*DKGRound2Message2, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentRound != 1 {
		return nil, nil, fmt.Errorf("not in round 1, current round: %d", p.currentRound)
	}

	// Update party with received messages
	for _, msg := range messages {
		if msg == nil {
			continue // Skip nil messages
		}
		if msg.FromPartyID == p.partyID.Id {
			continue // Skip our own messages
		}

		// Find the sender's party ID from our sorted list
		fromParty := p.findPartyID(msg.FromPartyID)
		if fromParty == nil {
			return nil, nil, fmt.Errorf("unknown sender party: %s", msg.FromPartyID)
		}

		parsedMsg, err := tss.ParseWireMessage(msg.MsgBytes, fromParty, msg.IsBroadcast)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing message from %s: %w", msg.FromPartyID, err)
		}

		ok, tssErr := p.party.Update(parsedMsg)
		if tssErr != nil {
			return nil, nil, fmt.Errorf("updating party with message from %s: %v (cause: %v)", msg.FromPartyID, tssErr, tssErr.Cause())
		}
		if !ok {
			return nil, nil, fmt.Errorf("update returned false for message from %s", msg.FromPartyID)
		}
	}

	p.currentRound = 2

	// Collect Round 2 messages
	return p.collectRound2Messages()
}

// findPartyID finds a party ID by its string identifier.
func (p *DKGParticipant) findPartyID(id string) *tss.PartyID {
	for _, party := range p.allParties {
		if party.Id == id {
			return party
		}
	}
	return nil
}

// collectRound2Messages collects messages from outCh for round 2.
func (p *DKGParticipant) collectRound2Messages() ([]*DKGRound2Message1, []*DKGRound2Message2, error) {
	var p2pMsgs []*DKGRound2Message1
	var bcMsgs []*DKGRound2Message2

	// Collect messages with timeout
	timeout := time.After(DKGRoundTimeout)

	for {
		select {
		case msg := <-p.outCh:
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				return nil, nil, fmt.Errorf("serializing message: %w", err)
			}

			if routing.IsBroadcast {
				bcMsgs = append(bcMsgs, &DKGRound2Message2{
					FromPartyID: p.partyID.Id,
					IsBroadcast: true,
					MsgBytes:    msgBytes,
				})
			} else {
				// P2P message - need to determine recipient
				for _, to := range routing.To {
					p2pMsgs = append(p2pMsgs, &DKGRound2Message1{
						FromPartyID: p.partyID.Id,
						ToPartyID:   to.Id,
						MsgBytes:    msgBytes,
					})
				}
			}

		case err := <-p.errCh:
			return nil, nil, fmt.Errorf("DKG error: %w", err.Cause())

		case <-timeout:
			// Return what we have
			return p2pMsgs, bcMsgs, nil
		}
	}
}

// ProcessRound2 handles incoming Round 2 messages and produces Round 3 messages.
func (p *DKGParticipant) ProcessRound2(p2pMsgs []*DKGRound2Message1, bcMsgs []*DKGRound2Message2) ([]*DKGRound3Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentRound != 2 {
		return nil, fmt.Errorf("not in round 2, current round: %d", p.currentRound)
	}

	// Process P2P messages
	for _, msg := range p2pMsgs {
		if msg == nil {
			continue
		}
		if msg.FromPartyID == p.partyID.Id {
			continue
		}
		if msg.ToPartyID != p.partyID.Id {
			continue // Not for us
		}

		// Find the sender's party ID from our sorted list
		fromParty := p.findPartyID(msg.FromPartyID)
		if fromParty == nil {
			return nil, fmt.Errorf("unknown sender party: %s", msg.FromPartyID)
		}

		parsedMsg, err := tss.ParseWireMessage(msg.MsgBytes, fromParty, false)
		if err != nil {
			return nil, fmt.Errorf("parsing P2P message from %s: %w", msg.FromPartyID, err)
		}

		ok, tssErr := p.party.Update(parsedMsg)
		if tssErr != nil {
			return nil, fmt.Errorf("updating party with P2P message from %s: %v (cause: %v)", msg.FromPartyID, tssErr, tssErr.Cause())
		}
		if !ok {
			return nil, fmt.Errorf("update returned false for P2P message from %s", msg.FromPartyID)
		}
	}

	// Process broadcast messages
	for _, msg := range bcMsgs {
		if msg == nil {
			continue
		}
		if msg.FromPartyID == p.partyID.Id {
			continue
		}

		// Find the sender's party ID from our sorted list
		fromParty := p.findPartyID(msg.FromPartyID)
		if fromParty == nil {
			return nil, fmt.Errorf("unknown sender party: %s", msg.FromPartyID)
		}

		parsedMsg, err := tss.ParseWireMessage(msg.MsgBytes, fromParty, true)
		if err != nil {
			return nil, fmt.Errorf("parsing broadcast message from %s: %w", msg.FromPartyID, err)
		}

		ok, tssErr := p.party.Update(parsedMsg)
		if tssErr != nil {
			return nil, fmt.Errorf("updating party with broadcast message from %s: %v (cause: %v)", msg.FromPartyID, tssErr, tssErr.Cause())
		}
		if !ok {
			return nil, fmt.Errorf("update returned false for broadcast message from %s", msg.FromPartyID)
		}
	}

	p.currentRound = 3

	// Collect Round 3 messages
	return p.collectRound3Messages()
}

// collectRound3Messages collects messages from outCh for round 3.
func (p *DKGParticipant) collectRound3Messages() ([]*DKGRound3Message, error) {
	var messages []*DKGRound3Message

	// Collect messages with timeout
	timeout := time.After(DKGRoundTimeout)

	for {
		select {
		case msg := <-p.outCh:
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				return nil, fmt.Errorf("serializing message: %w", err)
			}

			messages = append(messages, &DKGRound3Message{
				FromPartyID: p.partyID.Id,
				IsBroadcast: routing.IsBroadcast,
				MsgBytes:    msgBytes,
			})

			// Return after getting all messages
			if routing.IsBroadcast {
				return messages, nil
			}

		case result := <-p.endCh:
			// DKG complete
			p.result = result
			p.completed = true
			return messages, nil

		case err := <-p.errCh:
			return nil, fmt.Errorf("DKG error: %w", err.Cause())

		case <-timeout:
			return messages, nil
		}
	}
}

// ProcessRound3 handles incoming Round 3 messages and finalizes DKG.
func (p *DKGParticipant) ProcessRound3(messages []*DKGRound3Message) (*ECDSAKeyShare, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentRound != 3 {
		return nil, fmt.Errorf("not in round 3, current round: %d", p.currentRound)
	}

	// If already completed during round 3 collection
	if p.completed && p.result != nil {
		return &ECDSAKeyShare{
			PartyID:      p.partyID.Id,
			SaveData:     p.result,
			Threshold:    p.params.Threshold(),
			TotalParties: p.params.PartyCount(),
		}, nil
	}

	// Process Round 3 messages
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		if msg.FromPartyID == p.partyID.Id {
			continue
		}

		// Find the sender's party ID from our sorted list
		fromParty := p.findPartyID(msg.FromPartyID)
		if fromParty == nil {
			return nil, fmt.Errorf("unknown sender party: %s", msg.FromPartyID)
		}

		parsedMsg, err := tss.ParseWireMessage(msg.MsgBytes, fromParty, msg.IsBroadcast)
		if err != nil {
			return nil, fmt.Errorf("parsing round 3 message from %s: %w", msg.FromPartyID, err)
		}

		ok, tssErr := p.party.Update(parsedMsg)
		if tssErr != nil {
			return nil, fmt.Errorf("updating party with round 3 message from %s: %v (cause: %v)", msg.FromPartyID, tssErr, tssErr.Cause())
		}
		if !ok {
			return nil, fmt.Errorf("update returned false for round 3 message from %s", msg.FromPartyID)
		}
	}

	// Wait for completion, draining any pending output messages
	timeout := time.After(DKGRoundTimeout)
	for {
		select {
		case result := <-p.endCh:
			p.result = result
			p.completed = true

			return &ECDSAKeyShare{
				PartyID:      p.partyID.Id,
				SaveData:     result,
				Threshold:    p.params.Threshold(),
				TotalParties: p.params.PartyCount(),
			}, nil

		case err := <-p.errCh:
			return nil, fmt.Errorf("DKG error: %w", err.Cause())

		case <-p.outCh:
			// Drain any pending output messages (may happen during finalization)
			continue

		case <-timeout:
			return nil, fmt.Errorf("DKG timeout waiting for completion")
		}
	}
}

// IsComplete returns true if DKG is finished.
func (p *DKGParticipant) IsComplete() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completed
}

// CurrentRound returns the current DKG round (1-3).
func (p *DKGParticipant) CurrentRound() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentRound
}

// PartyID returns the participant's party ID string.
func (p *DKGParticipant) PartyID() string {
	return p.partyID.Id
}

// PartyIDFromInt creates a party ID string from an integer.
func PartyIDFromInt(id int) string {
	return fmt.Sprintf("party-%d", id)
}

// IntFromPartyID extracts the integer ID from a party ID string.
func IntFromPartyID(partyID string) (int, error) {
	var id int
	_, err := fmt.Sscanf(partyID, "party-%d", &id)
	return id, err
}

// SortedPartyIDs returns sorted party IDs for a given set of participants.
func SortedPartyIDs(ids []int) []string {
	sorted := make([]int, len(ids))
	copy(sorted, ids)
	sort.Ints(sorted)

	result := make([]string, len(sorted))
	for i, id := range sorted {
		result[i] = PartyIDFromInt(id)
	}
	return result
}

// KeyShareJSON is the JSON serialization format for ECDSAKeyShare.
type KeyShareJSON struct {
	PartyID      string `json:"party_id"`
	SaveData     []byte `json:"save_data"`
	Threshold    int    `json:"threshold"`
	TotalParties int    `json:"total_parties"`
}

// MarshalJSON implements json.Marshaler for ECDSAKeyShare.
func (k *ECDSAKeyShare) MarshalJSON() ([]byte, error) {
	saveDataBytes, err := json.Marshal(k.SaveData)
	if err != nil {
		return nil, err
	}

	return json.Marshal(KeyShareJSON{
		PartyID:      k.PartyID,
		SaveData:     saveDataBytes,
		Threshold:    k.Threshold,
		TotalParties: k.TotalParties,
	})
}

// UnmarshalJSON implements json.Unmarshaler for ECDSAKeyShare.
func (k *ECDSAKeyShare) UnmarshalJSON(data []byte) error {
	var j KeyShareJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	var saveData keygen.LocalPartySaveData
	if err := json.Unmarshal(j.SaveData, &saveData); err != nil {
		return err
	}

	k.PartyID = j.PartyID
	k.SaveData = &saveData
	k.Threshold = j.Threshold
	k.TotalParties = j.TotalParties

	return nil
}
