package session

import (
	"errors"
	"fmt"
	"io"

	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/group"
)

// Participant manages a single participant's state throughout DKG and signing
// ceremonies. Create instances using [NewParticipant].
type Participant struct {
	id        int
	frost     *frost.FROST
	group     group.Group
	keyShare  *frost.KeyShare
	dkgState  *frost.Participant
	finalized bool
}

// DKGResult contains the output of a successful DKG ceremony.
type DKGResult struct {
	// KeyShare is this participant's share of the distributed key.
	// Store this securely; it is required for signing.
	KeyShare *frost.KeyShare

	// GroupKey is the combined public key for the threshold group.
	// This is the same for all participants and is used to verify signatures.
	GroupKey group.Point

	// AllPublicKeys maps participant IDs to their individual public keys.
	// This can be used to verify each participant's contributions.
	AllPublicKeys map[int]group.Point
}

// Round1Output contains all messages generated during DKG round 1.
type Round1Output struct {
	// Broadcast is the public commitment that must be sent to all participants.
	Broadcast *frost.Round1Data

	// PrivateShares maps recipient participant ID to their private share.
	// Each share must be sent to its recipient over a secure, authenticated channel.
	PrivateShares map[int]*frost.Round1PrivateData
}

// Round1Input contains all messages received during DKG round 1.
type Round1Input struct {
	// Broadcasts contains the public commitments from all participants
	// (including this participant's own broadcast).
	Broadcasts []*frost.Round1Data

	// PrivateShares contains the private shares sent TO this participant
	// from all other participants.
	PrivateShares []*frost.Round1PrivateData
}

// NewParticipant creates a new participant for FROST ceremonies.
//
// Parameters:
//   - g: The cryptographic group to use (e.g., bjj.BJJ{})
//   - threshold: Minimum number of signers required (t)
//   - total: Total number of participants (n)
//   - id: This participant's unique identifier (1 to n)
//
// The returned Participant can be used for one DKG ceremony and then
// for multiple signing sessions.
func NewParticipant(g group.Group, threshold, total, id int) (*Participant, error) {
	if id < 1 || id > total {
		return nil, fmt.Errorf("participant ID must be between 1 and %d, got %d", total, id)
	}

	f, err := frost.New(g, threshold, total)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST instance: %w", err)
	}

	return &Participant{
		id:    id,
		frost: f,
		group: g,
	}, nil
}

// NewParticipantWithHasher creates a participant with a custom hash function.
// Use this for Ledger/iden3 compatibility with [frost.Blake2bHasher].
func NewParticipantWithHasher(g group.Group, threshold, total, id int, hasher frost.Hasher) (*Participant, error) {
	if id < 1 || id > total {
		return nil, fmt.Errorf("participant ID must be between 1 and %d, got %d", total, id)
	}

	f, err := frost.NewWithHasher(g, threshold, total, hasher)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST instance: %w", err)
	}

	return &Participant{
		id:    id,
		frost: f,
		group: g,
	}, nil
}

// ID returns this participant's identifier.
func (p *Participant) ID() int {
	return p.id
}

// KeyShare returns this participant's key share after DKG completion.
// Returns nil if DKG has not been finalized.
func (p *Participant) KeyShare() *frost.KeyShare {
	return p.keyShare
}

// FROST returns the underlying FROST instance for advanced use cases.
func (p *Participant) FROST() *frost.FROST {
	return p.frost
}

// GenerateRound1 generates all round 1 DKG messages.
//
// This creates:
//   - A public broadcast containing commitments to the secret polynomial
//   - Private shares for each other participant
//
// The broadcast should be sent to all participants. Each private share
// should be sent only to its intended recipient over a secure channel.
func (p *Participant) GenerateRound1(rng io.Reader, allParticipantIDs []int) (*Round1Output, error) {
	if p.dkgState != nil {
		return nil, errors.New("round 1 already generated")
	}

	// Create internal participant state
	participant, err := p.frost.NewParticipant(rng, p.id)
	if err != nil {
		return nil, fmt.Errorf("failed to create participant: %w", err)
	}
	p.dkgState = participant

	// Generate broadcast
	broadcast := participant.Round1Broadcast()

	// Generate private shares for all other participants
	privateShares := make(map[int]*frost.Round1PrivateData)
	for _, recipientID := range allParticipantIDs {
		if recipientID == p.id {
			continue // don't send to ourselves
		}
		share := p.frost.Round1PrivateSend(participant, recipientID)
		privateShares[recipientID] = share
	}

	return &Round1Output{
		Broadcast:     broadcast,
		PrivateShares: privateShares,
	}, nil
}

// ProcessRound1 processes received round 1 messages and completes the DKG.
//
// This verifies all received shares against their sender's commitments,
// then computes the final key share. After this call, the participant
// is ready for signing operations.
//
// The input must contain:
//   - Broadcasts from ALL participants (including this one)
//   - Private shares from all OTHER participants
func (p *Participant) ProcessRound1(input *Round1Input) (*DKGResult, error) {
	if p.dkgState == nil {
		return nil, errors.New("must call GenerateRound1 before ProcessRound1")
	}
	if p.finalized {
		return nil, errors.New("DKG already finalized")
	}

	// Build a map of broadcasts by sender ID for lookup
	broadcastByID := make(map[string]*frost.Round1Data)
	for _, b := range input.Broadcasts {
		key := string(b.ID.Bytes())
		if _, exists := broadcastByID[key]; exists {
			return nil, fmt.Errorf("duplicate broadcast from participant")
		}
		broadcastByID[key] = b
	}

	// Verify and receive each share
	for _, share := range input.PrivateShares {
		senderBroadcast, ok := broadcastByID[string(share.FromID.Bytes())]
		if !ok {
			return nil, fmt.Errorf("missing broadcast from sender of private share")
		}

		err := p.frost.Round2ReceiveShare(p.dkgState, share, senderBroadcast.Commitments)
		if err != nil {
			return nil, fmt.Errorf("invalid share from participant: %w", err)
		}
	}

	// Finalize to get key share
	keyShare, err := p.frost.Finalize(p.dkgState, input.Broadcasts)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize DKG: %w", err)
	}

	p.keyShare = keyShare
	p.finalized = true
	p.dkgState = nil // clear DKG state, no longer needed

	// Build public keys map
	allPublicKeys := make(map[int]group.Point)
	for _, b := range input.Broadcasts {
		// The first commitment (index 0) is the public key for that participant
		// Actually, individual public keys would need to be computed from the key shares
		// For now, we just store the constant term commitment
		id := scalarToInt(b.ID)
		allPublicKeys[id] = b.Commitments[0]
	}

	return &DKGResult{
		KeyShare:      keyShare,
		GroupKey:      keyShare.GroupKey,
		AllPublicKeys: allPublicKeys,
	}, nil
}

// SetKeyShare allows setting a previously-saved key share.
// Use this when restoring a participant from persistent storage.
func (p *Participant) SetKeyShare(ks *frost.KeyShare) {
	p.keyShare = ks
	p.finalized = true
}

// scalarToInt extracts the integer value from a scalar.
// This assumes the scalar represents a small integer (participant ID).
// Reads the last 4 bytes as a big-endian uint32 to support IDs up to 2^32-1.
func scalarToInt(s group.Scalar) int {
	b := s.Bytes()
	if len(b) == 0 {
		return 0
	}
	// Verify no significant bytes beyond the last 4 (participant IDs should be small)
	start := len(b) - 4
	if start < 0 {
		start = 0
	}
	for i := 0; i < start; i++ {
		if b[i] != 0 {
			panic("scalarToInt: scalar value exceeds uint32 range (invalid participant ID)")
		}
	}
	// Read up to the last 4 bytes as big-endian
	n := 0
	for _, v := range b[start:] {
		n = n<<8 | int(v)
	}
	return n
}
