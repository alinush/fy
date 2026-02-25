package dkg

import (
	"errors"
	"fmt"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/group"
)

// RefreshPhase1Output is the output of refresh phase 1.
type RefreshPhase1Output struct {
	// Deltas maps counterparty index to the zero-polynomial evaluation for that party.
	// These must be sent over a secure, authenticated channel.
	Deltas map[uint8]group.Scalar

	// Commitments are Feldman VSS commitments: Commitments[i] = zeroCoeffs[i] * G.
	// Commitments[0] must be the identity point (since zeroCoeffs[0] = 0).
	// Broadcast these to all participants for delta verification.
	Commitments []group.Point

	// Keep holds state needed for RefreshPhase2.
	Keep *RefreshPhase1Keep
}

// RefreshPhase1Keep holds state between refresh phase 1 and phase 2.
type RefreshPhase1Keep struct {
	ownDelta   group.Scalar
	zeroCoeffs []group.Scalar
}

// RefreshPhase1 generates a zero-polynomial and evaluates it at all party
// indices. This is the first step of the DKLs23 refresh protocol.
//
// The zero-polynomial has coefficients[0] = 0, so the sum of all participants'
// polynomials preserves the group secret while changing individual shares.
// All n participants must participate in the refresh.
func RefreshPhase1(data *SessionData) (*RefreshPhase1Output, error) {
	if err := data.ValidateSession(); err != nil {
		return nil, err
	}

	// Generate zero-polynomial of degree t-1 with coefficients[0] = 0.
	zeroCoeffs := make([]group.Scalar, data.Parameters.Threshold)
	zeroCoeffs[0] = dkls23.NewScalar() // zero

	for i := uint8(1); i < data.Parameters.Threshold; i++ {
		s, err := dkls23.RandomScalar()
		if err != nil {
			return nil, err
		}
		zeroCoeffs[i] = s
	}

	// Compute Feldman VSS commitments: Commitments[i] = zeroCoeffs[i] * G.
	commitments := make([]group.Point, data.Parameters.Threshold)
	for i, c := range zeroCoeffs {
		commitments[i] = dkls23.ScalarBaseMult(c)
	}

	// Evaluate at all party indices using Horner's method.
	deltas := make(map[uint8]group.Scalar)
	var ownDelta group.Scalar

	for j := uint8(1); j <= data.Parameters.ShareCount; j++ {
		jScalar := dkls23.NewScalar()
		// Values in [1, MaxShareCount] are always within group order.
		jScalar.SetBytes([]byte{j})

		lastIndex := data.Parameters.Threshold - 1
		evaluation := dkls23.NewScalar().Set(zeroCoeffs[lastIndex])
		for k := int(lastIndex) - 1; k >= 0; k-- {
			evaluation = dkls23.ScalarAdd(dkls23.ScalarMul(evaluation, jScalar), zeroCoeffs[k])
		}

		if j == data.PartyIndex {
			ownDelta = evaluation
		} else {
			deltas[j] = evaluation
		}
	}

	return &RefreshPhase1Output{
		Deltas:      deltas,
		Commitments: commitments,
		Keep: &RefreshPhase1Keep{
			ownDelta:   ownDelta,
			zeroCoeffs: zeroCoeffs,
		},
	}, nil
}

// RefreshVerifyDelta verifies a received delta against the sender's Feldman
// VSS commitments. The verification checks:
//
//	delta * G == sum(Commitment[i] * recipientIndex^i)
//
// Call this for each received delta before passing them to [RefreshPhase2].
//
// Session binding: each refresh run generates fresh random polynomial
// coefficients and commitments. A delta replayed from a previous run will
// fail verification against the current run's commitments.
func RefreshVerifyDelta(delta group.Scalar, recipientIndex uint8, senderCommitments []group.Point) error {
	// LHS: delta * G
	lhs := dkls23.ScalarBaseMult(delta)

	// RHS: sum(Commitment[i] * recipientIndex^i)
	xScalar := dkls23.NewScalar()
	// Values in [1, MaxShareCount] are always within group order.
	xScalar.SetBytes([]byte{recipientIndex})

	rhs := dkls23.NewPoint()
	xPower := dkls23.NewScalar()
	// SetBytes([]byte{1}) always succeeds for small integers.
	xPower.SetBytes([]byte{1})

	for _, commit := range senderCommitments {
		term := dkls23.ScalarMult(commit, xPower)
		rhs = dkls23.PointAdd(rhs, term)
		xPower = dkls23.ScalarMul(xPower, xScalar)
	}

	if !dkls23.PointEqual(lhs, rhs) {
		return errors.New("invalid refresh delta (Feldman VSS failed)")
	}
	return nil
}

// RefreshPhase2 computes the refreshed key share and produces a [Phase2Output]
// that is compatible with the standard DKG [Phase3] and [Phase4] functions.
//
// After calling RefreshPhase2, continue with the standard DKG Phase3 and
// Phase4 to re-initialize zero seeds and MtA/OT correlations.
//
// The allCommitments parameter contains Feldman VSS commitments from all
// participants (including self), keyed by party index. These are used for
// cheating detection: the sum of all commitments[0] must equal the identity
// point, confirming every participant used a zero-polynomial.
//
// Callers MUST verify each received delta via [RefreshVerifyDelta] before
// calling this function.
func RefreshPhase2(data *SessionData, keep *RefreshPhase1Keep, existingKeyShare group.Scalar, receivedDeltas map[uint8]group.Scalar, allCommitments map[uint8][]group.Point) (*Phase2Output, error) {
	// Cheating detection: sum of all commitments[0] must equal identity.
	// Since each participant's zeroCoeffs[0] = 0, each commitments[0]
	// should be identity, and their sum must also be identity.
	if len(allCommitments) != int(data.Parameters.ShareCount) {
		return nil, fmt.Errorf("expected commitments from %d participants, got %d", data.Parameters.ShareCount, len(allCommitments))
	}
	sumC0 := dkls23.NewPoint()
	for _, commitments := range allCommitments {
		if len(commitments) == 0 {
			return nil, errors.New("refresh: participant has empty commitments")
		}
		sumC0 = dkls23.PointAdd(sumC0, commitments[0])
	}
	if !dkls23.IsIdentity(sumC0) {
		return nil, errors.New("refresh: sum of constant-term commitments is not identity (cheating detected)")
	}

	// Verify we received deltas from all counterparties.
	expectedDeltas := int(data.Parameters.ShareCount) - 1
	if len(receivedDeltas) != expectedDeltas {
		return nil, fmt.Errorf("expected %d deltas, got %d", expectedDeltas, len(receivedDeltas))
	}

	// Sum all deltas: ownDelta + sum(receivedDeltas).
	totalDelta := dkls23.NewScalar().Set(keep.ownDelta)
	for _, delta := range receivedDeltas {
		totalDelta = dkls23.ScalarAdd(totalDelta, delta)
	}

	// New key share = existing + totalDelta.
	newPolyPoint := dkls23.ScalarAdd(existingKeyShare, totalDelta)

	// Zero sensitive state.
	for i := range keep.zeroCoeffs {
		keep.zeroCoeffs[i].Zero()
	}
	keep.zeroCoeffs = nil
	keep.ownDelta.Zero()

	// Reuse standard Phase2: pass the new key share as the sole "fragment".
	// Step3 inside Phase2 sums a single-element slice, yielding newPolyPoint.
	return Phase2(data, []group.Scalar{newPolyPoint})
}

// Zero securely erases all secret material from RefreshPhase1Keep.
// Call this to clean up if the refresh protocol is aborted.
func (k *RefreshPhase1Keep) Zero() {
	if k == nil {
		return
	}
	if k.ownDelta != nil {
		k.ownDelta.Zero()
	}
	for i := range k.zeroCoeffs {
		if k.zeroCoeffs[i] != nil {
			k.zeroCoeffs[i].Zero()
		}
	}
	k.zeroCoeffs = nil
}

// VerifyRefreshedPublicKey checks that a refreshed party's public key matches
// the expected public key from before refresh. Call this after Phase4 completes.
func VerifyRefreshedPublicKey(expected, actual group.Point) error {
	if !dkls23.PointEqual(expected, actual) {
		return errors.New("refresh: public key not preserved")
	}
	return nil
}
