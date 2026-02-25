package frost

import (
	"errors"
	"fmt"
	"io"

	"github.com/f3rmion/fy/group"
)

// RefreshParticipant holds the state for a participant during the refresh
// protocol (proactive share rotation). Each participant generates a
// zero-polynomial (constant term = 0) so that the sum of all participants'
// polynomials preserves the group secret while changing individual shares.
//
// Create instances using [FROST.NewRefreshParticipant].
type RefreshParticipant struct {
	id             group.Scalar
	coefficients   []group.Scalar // coefficients[0] == 0 (invariant)
	commitments    []group.Point
	receivedDeltas map[string]group.Scalar // deltas from other participants
}

// RefreshRound1Data is the public data broadcast by a participant during
// the refresh protocol. Recipients use the commitments to verify received
// deltas via Feldman VSS.
type RefreshRound1Data struct {
	// ID is the unique identifier of the broadcasting participant.
	ID group.Scalar

	// Commitments are commitments to the zero-polynomial coefficients.
	// Commitments[0] must be the identity point (since coefficients[0] = 0).
	Commitments []group.Point
}

// RefreshRound1PrivateData is the private delta sent from one participant
// to a specific recipient during the refresh protocol. This data must be
// sent over a secure, authenticated channel.
type RefreshRound1PrivateData struct {
	// FromID is the sender's participant identifier.
	FromID group.Scalar

	// ToID is the intended recipient's participant identifier.
	ToID group.Scalar

	// Delta is the sender's zero-polynomial evaluated at the recipient's ID.
	Delta group.Scalar
}

// NewRefreshParticipant creates a new participant for the refresh protocol.
//
// The participant generates a zero-polynomial: coefficients[0] = 0 and
// coefficients[1..threshold-1] are random. Since the constant term is zero,
// the sum of all participants' zero-polynomials evaluated at any point
// contributes nothing to the reconstructed secret, preserving the group key.
//
// The id parameter must be the participant's existing scalar identifier
// (from their [KeyShare.ID]). The random reader r is used to generate the
// random polynomial coefficients.
func (f *FROST) NewRefreshParticipant(r io.Reader, id group.Scalar) (*RefreshParticipant, error) {
	if id.IsZero() {
		return nil, errors.New("participant ID must be non-zero")
	}

	// Generate zero-polynomial of degree t-1 with coefficients[0] = 0.
	coeffs := make([]group.Scalar, f.threshold)
	coeffs[0] = f.group.NewScalar() // zero

	for i := 1; i < f.threshold; i++ {
		c, err := f.group.RandomScalar(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}

	// Compute commitments: commitments[i] = coefficients[i] * G.
	commits := make([]group.Point, f.threshold)
	for i, c := range coeffs {
		commits[i] = f.group.NewPoint().ScalarMult(c, f.group.Generator())
	}

	// Sanity check: commitments[0] must be the identity point since
	// coefficients[0] = 0 and 0 * G = identity.
	if !commits[0].IsIdentity() {
		return nil, errors.New("refresh: commitments[0] is not identity (zero-polynomial invariant violated)")
	}

	return &RefreshParticipant{
		id:             id,
		coefficients:   coeffs,
		commitments:    commits,
		receivedDeltas: make(map[string]group.Scalar),
	}, nil
}

// Round1Broadcast returns the public data that this refresh participant must
// broadcast to all other participants.
func (rp *RefreshParticipant) Round1Broadcast() *RefreshRound1Data {
	return &RefreshRound1Data{
		ID:          rp.id,
		Commitments: rp.commitments,
	}
}

// RefreshRound1PrivateSend computes and returns the private delta that
// participant rp must send to the specified recipient. The delta is the
// evaluation of rp's zero-polynomial at the recipient's ID.
//
// This data must be transmitted over a secure, authenticated channel.
func (f *FROST) RefreshRound1PrivateSend(rp *RefreshParticipant, recipientID group.Scalar) (*RefreshRound1PrivateData, error) {
	if recipientID.IsZero() {
		return nil, errors.New("recipient ID must be non-zero")
	}
	delta := f.evalPolynomial(rp.coefficients, recipientID)

	return &RefreshRound1PrivateData{
		FromID: rp.id,
		ToID:   recipientID,
		Delta:  delta,
	}, nil
}

// RefreshRound2ReceiveDelta verifies a received delta against the sender's
// public commitments and stores it if valid. Returns an error if the delta
// fails verification, indicating a potentially malicious sender.
//
// The verification uses Feldman's VSS scheme: it checks that
// delta * G == sum(Commitment[i] * recipientID^i).
//
// Session binding: each refresh run generates fresh random polynomial
// coefficients and commitments. A delta replayed from a previous run will
// fail Feldman VSS verification against the current run's commitments.
func (f *FROST) RefreshRound2ReceiveDelta(rp *RefreshParticipant, data *RefreshRound1PrivateData, senderCommitments []group.Point) error {
	// Verify the delta is intended for this participant.
	if !data.ToID.Equal(rp.id) {
		return errors.New("refresh delta intended for a different recipient")
	}

	// Verify: delta * G == sum(commitments[i] * recipientID^i)
	lhs := f.group.NewPoint().ScalarMult(data.Delta, f.group.Generator())

	rhs := f.group.NewPoint()
	xPower := f.scalarFromInt(1)

	for _, commit := range senderCommitments {
		term := f.group.NewPoint().ScalarMult(xPower, commit)
		rhs = f.group.NewPoint().Add(rhs, term)
		xPower = f.group.NewScalar().Mul(xPower, data.ToID)
	}

	if !lhs.Equal(rhs) {
		return errors.New("invalid refresh delta from participant")
	}

	// Store the delta keyed by sender ID bytes.
	key := string(data.FromID.Bytes())
	if _, exists := rp.receivedDeltas[key]; exists {
		return errors.New("duplicate refresh delta from participant")
	}
	rp.receivedDeltas[key] = data.Delta
	return nil
}

// RefreshFinalize completes the refresh protocol for participant rp, computing
// their new key share. This should be called after all deltas have been
// received and verified via [FROST.RefreshRound2ReceiveDelta].
//
// The returned [KeyShare] contains the participant's new secret key share
// and the SAME group public key as before. Old shares become invalid after
// refresh.
//
// All n participants must participate in the refresh protocol (not just
// threshold). The allBroadcasts slice must contain broadcasts from every
// participant including rp itself.
func (f *FROST) RefreshFinalize(rp *RefreshParticipant, existingShare *KeyShare, allBroadcasts []*RefreshRound1Data) (*KeyShare, error) {
	// All n participants must participate in refresh.
	if len(allBroadcasts) != f.total {
		return nil, fmt.Errorf("refresh requires all %d participants, got %d broadcasts", f.total, len(allBroadcasts))
	}

	// Cheating detection: sum of all Commitments[0] must equal identity.
	// Since each participant's coefficients[0] = 0, each Commitments[0]
	// should be identity, and their sum must also be identity.
	sumC0 := f.group.NewPoint()
	for _, b := range allBroadcasts {
		if len(b.Commitments) == 0 {
			return nil, errors.New("refresh: broadcast has empty commitments")
		}
		sumC0 = f.group.NewPoint().Add(sumC0, b.Commitments[0])
	}
	if !sumC0.IsIdentity() {
		return nil, errors.New("refresh: sum of constant-term commitments is not identity (cheating detected)")
	}

	// Verify we received deltas from all other participants (total - 1).
	expectedDeltas := f.total - 1
	if len(rp.receivedDeltas) != expectedDeltas {
		return nil, fmt.Errorf("expected %d deltas from other participants, got %d", expectedDeltas, len(rp.receivedDeltas))
	}

	// Compute own delta = evalPolynomial(rp.coefficients, rp.id).
	ownDelta := f.evalPolynomial(rp.coefficients, rp.id)

	// newSecret = existingShare.SecretKey + ownDelta + sum(receivedDeltas).
	newSecret := f.group.NewScalar().Add(existingShare.SecretKey, ownDelta)
	for _, delta := range rp.receivedDeltas {
		newSecret = f.group.NewScalar().Add(newSecret, delta)
	}

	// newPublicKey = newSecret * G.
	newPublicKey := f.group.NewPoint().ScalarMult(newSecret, f.group.Generator())

	// Zero old coefficients and deltas to prevent memory residue.
	rp.Zero()

	return &KeyShare{
		ID:        existingShare.ID,
		SecretKey: newSecret,
		PublicKey: newPublicKey,
		GroupKey:  existingShare.GroupKey, // unchanged
	}, nil
}

// Zero securely erases all secret material held by the refresh participant.
// This is called automatically by [FROST.RefreshFinalize] but can also be
// called explicitly to clean up after an aborted refresh.
func (rp *RefreshParticipant) Zero() {
	for i := range rp.coefficients {
		rp.coefficients[i].Zero()
	}
	rp.coefficients = nil

	for key := range rp.receivedDeltas {
		rp.receivedDeltas[key].Zero()
	}
	rp.receivedDeltas = nil
}
