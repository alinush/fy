package frost

import (
	"errors"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// Round1Data contains the public data broadcast by a participant during
// round 1 of the DKG protocol. This includes commitments to the participant's
// secret polynomial coefficients.
type Round1Data struct {
	// ID is the unique identifier of the broadcasting participant.
	ID group.Scalar

	// Commitments are Pedersen commitments to the polynomial coefficients.
	// Commitments[i] = coefficients[i] * G, where G is the group generator.
	Commitments []group.Point
}

// Round1PrivateData contains the private share sent from one participant
// to another during round 1 of the DKG protocol. This data must be sent
// over a secure, authenticated channel.
type Round1PrivateData struct {
	// FromID is the sender's participant identifier.
	FromID group.Scalar

	// ToID is the intended recipient's participant identifier.
	ToID group.Scalar

	// Share is the sender's polynomial evaluated at the recipient's ID.
	// This value must be kept confidential during transmission.
	Share group.Scalar
}

// Participant holds the state for a single participant during the DKG protocol.
// Create instances using [FROST.NewParticipant].
type Participant struct {
	id             group.Scalar
	coefficients   []group.Scalar          // our secret polynomial
	commitments    []group.Point           // public commitments
	receivedShares map[string]group.Scalar // shares from others
}

// NewParticipant creates a new participant for the DKG protocol.
//
// The id parameter must be a unique integer from 1 to n (total participants).
// The random reader r is used to generate the participant's secret polynomial.
func (f *FROST) NewParticipant(r io.Reader, id int) (*Participant, error) {
	if id == 0 {
		return nil, errors.New("participant ID must be non-zero")
	}
	if id < 1 || id > f.total {
		return nil, fmt.Errorf("participant ID must be between 1 and %d, got %d", f.total, id)
	}

	// Generate random polynomial of degree t-1
	coeffs := make([]group.Scalar, f.threshold)
	for i := range f.threshold {
		c, err := f.group.RandomScalar(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}

	// Compute commitments: C_i = coeffs[i] * G
	commits := make([]group.Point, f.threshold)
	for i, c := range coeffs {
		commits[i] = f.group.NewPoint().ScalarMult(c, f.group.Generator())
	}

	return &Participant{
		id:             f.scalarFromInt(id),
		coefficients:   coeffs,
		commitments:    commits,
		receivedShares: make(map[string]group.Scalar),
	}, nil
}

// Round1Broadcast returns the public data that this participant must
// broadcast to all other participants. This includes commitments to
// the participant's secret polynomial.
func (p *Participant) Round1Broadcast() *Round1Data {
	return &Round1Data{
		ID:          p.id,
		Commitments: p.commitments,
	}
}

// Round1PrivateSend computes and returns the private share that participant p
// must send to the specified recipient. This data must be transmitted over a
// secure, authenticated channel.
func (f *FROST) Round1PrivateSend(p *Participant, recipientID int) *Round1PrivateData {
	toID := f.scalarFromInt(recipientID)
	share := f.evalPolynomial(p.coefficients, toID)

	return &Round1PrivateData{
		FromID: p.id,
		ToID:   toID,
		Share:  share,
	}
}

// Round2ReceiveShare verifies a received share against the sender's public
// commitments and stores it if valid. Returns an error if the share fails
// verification, indicating a potentially malicious sender.
//
// The verification uses Feldman's VSS scheme: it checks that
// share * G == sum(Commitment[i] * recipientID^i).
func (f *FROST) Round2ReceiveShare(p *Participant, data *Round1PrivateData, senderCommitments []group.Point) error {
	// Verify that the share is intended for this participant (check before
	// expensive VSS computation to fail fast on misrouted shares).
	if !data.ToID.Equal(p.id) {
		return errors.New("share intended for a different recipient")
	}

	// Verify: share * G == sum(commitments[i] * recipientID^i)
	lhs := f.group.NewPoint().ScalarMult(data.Share, f.group.Generator())

	rhs := f.group.NewPoint()
	xPower := f.scalarFromInt(1)

	for _, commit := range senderCommitments {
		term := f.group.NewPoint().ScalarMult(xPower, commit)
		rhs = f.group.NewPoint().Add(rhs, term)
		xPower = f.group.NewScalar().Mul(xPower, data.ToID)
	}

	if !lhs.Equal(rhs) {
		return errors.New("invalid share from participant")
	}

	// Store the share, rejecting duplicates
	key := string(data.FromID.Bytes())
	if _, exists := p.receivedShares[key]; exists {
		return fmt.Errorf("frost: duplicate DKG share from participant")
	}
	p.receivedShares[key] = data.Share
	return nil
}

// Finalize completes the DKG protocol for participant p, computing their
// final key share. This should be called after all shares have been received
// and verified via [FROST.Round2ReceiveShare].
//
// The returned [KeyShare] contains the participant's secret key share and
// the group's combined public key, which is the same for all participants.
func (f *FROST) Finalize(p *Participant, allBroadcasts []*Round1Data) (*KeyShare, error) {
	if len(allBroadcasts) != f.total {
		return nil, fmt.Errorf("expected %d broadcasts, got %d", f.total, len(allBroadcasts))
	}

	// Verify we received shares from all other participants
	expectedShares := len(allBroadcasts) - 1
	if len(p.receivedShares) != expectedShares {
		return nil, fmt.Errorf("expected %d shares from other participants, got %d", expectedShares, len(p.receivedShares))
	}
	// Sum all received shares (including our own)
	secretKey := f.evalPolynomial(p.coefficients, p.id)
	for _, share := range p.receivedShares {
		secretKey = f.group.NewScalar().Add(secretKey, share)
	}

	// Compute public key share
	publicKey := f.group.NewPoint().ScalarMult(secretKey, f.group.Generator())

	// Compute group public key: sum of all constant term commitments
	groupKey := f.group.NewPoint()
	for _, broadcast := range allBroadcasts {
		groupKey = f.group.NewPoint().Add(groupKey, broadcast.Commitments[0])
	}

	// Zero out secret DKG material now that the key share has been derived.
	// Coefficients encode the participant's secret polynomial and are the most
	// sensitive intermediate values — they must not persist beyond DKG completion.
	for i := range p.coefficients {
		p.coefficients[i].Zero()
	}
	p.coefficients = nil
	for _, share := range p.receivedShares {
		share.Zero()
	}
	p.receivedShares = nil

	return &KeyShare{
		ID:        p.id,
		SecretKey: secretKey,
		PublicKey: publicKey,
		GroupKey:  groupKey,
	}, nil
}
