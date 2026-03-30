package session

import (
	"errors"
	"fmt"
	"sync"

	"github.com/f3rmion/fy/dkls23/dkg"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// DKLS23Participant manages a single participant's state throughout DKLS23 DKG
// and signing ceremonies. Create instances using [NewDKLS23Participant].
type DKLS23Participant struct {
	mu        sync.Mutex
	index     uint8
	threshold uint8
	total     uint8
	sessionID []byte

	// DKG state
	dkgData      *dkg.SessionData
	phase1Output *dkg.Phase1Output
	phase2Output *dkg.Phase2Output
	phase3Output *dkg.Phase3Output
	dkgPhase     int

	// Signing party (after DKG completion)
	party *sign.Party
}

// DKLS23DKGPhase1Output contains all data generated during DKG phase 1.
type DKLS23DKGPhase1Output struct {
	// PolyPoints contains the polynomial evaluated at each party index.
	// Send PolyPoints[j-1] to party j (indices are 1-based).
	PolyPoints []group.Scalar
}

// DKLS23DKGPhase2Output contains all data generated during DKG phase 2.
type DKLS23DKGPhase2Output struct {
	// ProofCommitment is broadcast to all participants.
	ProofCommitment *dkg.ProofCommitment

	// ZeroCommitments maps recipient party index to their zero seed commitment.
	// Send ZeroCommitments[j] to party j.
	ZeroCommitments map[uint8]*dkg.Phase2to4ZeroTransmit
}

// DKLS23DKGPhase3Output contains all data generated during DKG phase 3.
type DKLS23DKGPhase3Output struct {
	// ZeroSeeds maps recipient party index to their revealed zero seed.
	// Send ZeroSeeds[j] to party j.
	ZeroSeeds map[uint8]*dkg.Phase3to4ZeroTransmit

	// MulInit maps recipient party index to multiplication initialization data.
	// Send MulInit[j] to party j.
	MulInit map[uint8]*dkg.Phase3to4MulTransmit
}

// DKLS23DKGPhase4Input contains all received messages for DKG phase 4.
type DKLS23DKGPhase4Input struct {
	// ProofCommitments from all participants (including self).
	ProofCommitments []*dkg.ProofCommitment

	// ZeroCommitments received from other participants in phase 2.
	ZeroCommitments []*dkg.Phase2to4ZeroTransmit

	// ZeroSeeds received from other participants in phase 3.
	ZeroSeeds []*dkg.Phase3to4ZeroTransmit

	// MulInit received from other participants in phase 3.
	MulInit []*dkg.Phase3to4MulTransmit
}

// NewDKLS23Participant creates a new participant for DKLS23 ceremonies.
//
// Parameters:
//   - threshold: Minimum number of signers required (t)
//   - total: Total number of participants (n)
//   - index: This participant's unique identifier (1 to n)
//   - sessionID: Unique session identifier for this DKG ceremony
func NewDKLS23Participant(threshold, total, index uint8, sessionID []byte) (*DKLS23Participant, error) {
	if index < 1 || index > total {
		return nil, errors.New("participant index must be between 1 and total")
	}
	if threshold < 2 || threshold > total {
		return nil, errors.New("threshold must be between 2 and total")
	}

	// Copy sessionID to prevent external modification
	sid := make([]byte, len(sessionID))
	copy(sid, sessionID)

	return &DKLS23Participant{
		index:     index,
		threshold: threshold,
		total:     total,
		sessionID: sid,
		dkgData: &dkg.SessionData{
			Parameters: dkg.Parameters{
				Threshold:  threshold,
				ShareCount: total,
			},
			PartyIndex: index,
			SessionID:  sid,
		},
		dkgPhase: 0,
	}, nil
}

// Index returns this participant's identifier.
func (p *DKLS23Participant) Index() uint8 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.index
}

// Party returns the signing party after DKG completion.
// Returns nil if DKG has not been finalized.
func (p *DKLS23Participant) Party() *sign.Party {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.party
}

// DKGPhase1 executes DKG phase 1: generate random polynomial and evaluate.
//
// This creates polynomial evaluations for all participants. Send
// PolyPoints[j-1] to party j.
func (p *DKLS23Participant) DKGPhase1() (*DKLS23DKGPhase1Output, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dkgPhase != 0 {
		return nil, errors.New("DKG phase 1 already completed")
	}

	phase1Out, err := dkg.Phase1(p.dkgData)
	if err != nil {
		return nil, err
	}
	p.phase1Output = phase1Out
	p.dkgPhase = 1

	// Return a copy of PolyPoints to prevent callers from mutating internal state.
	pts := make([]group.Scalar, len(p.phase1Output.PolyPoints))
	copy(pts, p.phase1Output.PolyPoints)

	return &DKLS23DKGPhase1Output{
		PolyPoints: pts,
	}, nil
}

// DKGPhase2 executes DKG phase 2: generate proof commitments and zero seeds.
//
// Parameters:
//   - receivedPolyPoints: Map from sender party index to their polynomial
//     evaluation for this participant. Must include evaluations from all
//     other participants.
func (p *DKLS23Participant) DKGPhase2(receivedPolyPoints map[uint8]group.Scalar) (*DKLS23DKGPhase2Output, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dkgPhase != 1 {
		return nil, errors.New("must complete DKG phase 1 before phase 2")
	}

	// Validate that we received polynomial points from exactly the other participants.
	if len(receivedPolyPoints) != int(p.total)-1 {
		return nil, fmt.Errorf("expected %d polynomial points, got %d", p.total-1, len(receivedPolyPoints))
	}

	// Collect polynomial fragments: our own + received from others
	polyFragments := make([]group.Scalar, 0, p.total)

	// Add our own fragment (evaluation at our index)
	polyFragments = append(polyFragments, p.phase1Output.PolyPoints[p.index-1])

	// Add received fragments
	for i := uint8(1); i <= p.total; i++ {
		if i == p.index {
			continue
		}
		fragment, ok := receivedPolyPoints[i]
		if !ok {
			return nil, errors.New("missing polynomial point from party")
		}
		polyFragments = append(polyFragments, fragment)
	}

	phase2Out, err := dkg.Phase2(p.dkgData, polyFragments)
	if err != nil {
		return nil, err
	}
	p.phase2Output = phase2Out
	p.dkgPhase = 2

	// Convert transmit slice to map for easier routing
	zeroCommitments := make(map[uint8]*dkg.Phase2to4ZeroTransmit)
	for _, msg := range p.phase2Output.ZeroTransmit {
		zeroCommitments[msg.Receiver] = msg
	}

	return &DKLS23DKGPhase2Output{
		ProofCommitment: p.phase2Output.ProofCommitment,
		ZeroCommitments: zeroCommitments,
	}, nil
}

// DKGPhase3 executes DKG phase 3: reveal zero seeds and initialize multiplication.
func (p *DKLS23Participant) DKGPhase3() (*DKLS23DKGPhase3Output, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dkgPhase != 2 {
		return nil, errors.New("must complete DKG phase 2 before phase 3")
	}

	var err error
	p.phase3Output, err = dkg.Phase3(p.dkgData, p.phase2Output.ZeroKeep)
	if err != nil {
		return nil, err
	}
	p.dkgPhase = 3

	// Convert transmit slices to maps for easier routing
	zeroSeeds := make(map[uint8]*dkg.Phase3to4ZeroTransmit)
	for _, msg := range p.phase3Output.ZeroTransmit {
		zeroSeeds[msg.Receiver] = msg
	}

	mulInit := make(map[uint8]*dkg.Phase3to4MulTransmit)
	for _, msg := range p.phase3Output.MulTransmit {
		mulInit[msg.Receiver] = msg
	}

	return &DKLS23DKGPhase3Output{
		ZeroSeeds: zeroSeeds,
		MulInit:   mulInit,
	}, nil
}

// DKGPhase4 executes DKG phase 4: verify proofs and finalize.
//
// After this call, the participant is ready for signing operations.
// Use [Party] to get the signing party.
func (p *DKLS23Participant) DKGPhase4(input *DKLS23DKGPhase4Input) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dkgPhase != 3 {
		return errors.New("must complete DKG phase 3 before phase 4")
	}

	phase4Input := &dkg.Phase4Input{
		PolyPoint:         p.phase2Output.PolyPoint,
		ProofsCommitments: input.ProofCommitments,
		ZeroKept:          p.phase3Output.ZeroKeep,
		ZeroReceived2:     input.ZeroCommitments,
		ZeroReceived3:     input.ZeroSeeds,
		MulKept:           p.phase3Output.MulKeep,
		MulReceived:       input.MulInit,
	}

	party, err := dkg.Phase4(p.dkgData, phase4Input)
	if err != nil {
		return err
	}

	p.party = party
	p.dkgPhase = 4

	// Clear DKG state
	p.phase1Output = nil
	p.phase2Output = nil
	p.phase3Output = nil
	p.dkgData = nil

	return nil
}

// SetParty allows setting a previously-saved signing party.
// Use this when restoring a participant from persistent storage.
func (p *DKLS23Participant) SetParty(party *sign.Party) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if party == nil {
		return errors.New("party cannot be nil")
	}
	p.party = party
	p.dkgPhase = 4
	return nil
}
