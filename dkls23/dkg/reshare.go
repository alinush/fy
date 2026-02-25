package dkg

import (
	"errors"
	"fmt"

	"github.com/f3rmion/fy/dkls23"
	"github.com/f3rmion/fy/dkls23/sign"
	"github.com/f3rmion/fy/group"
)

// ReshareOldMemberOutput contains the evaluated shares from an old committee
// member to distribute to new committee members.
type ReshareOldMemberOutput struct {
	// Shares maps new member index to their sub-share.
	// These must be sent over a secure, authenticated channel.
	Shares map[uint8]group.Scalar

	// Commitments are Feldman VSS commitments: Commitments[i] = coefficients[i] * G.
	// New members use these to verify received sub-shares.
	Commitments []group.Point
}

// Zero securely erases the sub-shares in the output. Callers MUST call this
// after all shares have been transmitted to new committee members.
func (o *ReshareOldMemberOutput) Zero() {
	if o == nil {
		return
	}
	for key := range o.Shares {
		o.Shares[key].Zero()
	}
	o.Shares = nil
}

// ReshareOldMemberKeep holds the polynomial coefficients for cleanup.
type ReshareOldMemberKeep struct {
	coefficients []group.Scalar
}

// ReshareOldMemberDistribute computes the Lagrange-weighted polynomial for
// this old committee member and evaluates it at each new member's index.
//
// At least t_old old members must participate (len(oldMemberIndices) >= t_old).
// The newThreshold specifies the threshold for the new committee.
// The newMemberIndices lists the indices of all new committee members.
func ReshareOldMemberDistribute(
	existingParty *sign.Party,
	oldMemberIndices []uint8,
	newThreshold uint8,
	newMemberIndices []uint8,
) (*ReshareOldMemberOutput, *ReshareOldMemberKeep, error) {
	if int(existingParty.Threshold) > len(oldMemberIndices) {
		return nil, nil, fmt.Errorf("need at least %d old members, got %d", existingParty.Threshold, len(oldMemberIndices))
	}
	if newThreshold < 2 {
		return nil, nil, errors.New("new threshold must be at least 2")
	}
	if len(newMemberIndices) < int(newThreshold) {
		return nil, nil, errors.New("need at least newThreshold new members")
	}

	// Verify our index is in oldMemberIndices.
	found := false
	for _, idx := range oldMemberIndices {
		if idx == existingParty.Index {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, errors.New("party index not in old member list")
	}

	// Check for duplicate old member indices.
	seen := make(map[uint8]bool, len(oldMemberIndices))
	for _, idx := range oldMemberIndices {
		if seen[idx] {
			return nil, nil, errors.New("duplicate old member index")
		}
		seen[idx] = true
	}

	// Validate new member indices: must be >= 1 (index 0 would leak
	// the weighted secret since evalPolynomialAt(coeffs, 0) = coeffs[0] = lambda * keyShare).
	seenNew := make(map[uint8]bool, len(newMemberIndices))
	for _, idx := range newMemberIndices {
		if idx == 0 {
			return nil, nil, errors.New("new member index must be >= 1")
		}
		if seenNew[idx] {
			return nil, nil, errors.New("duplicate new member index")
		}
		seenNew[idx] = true
	}

	// Compute Lagrange coefficient among old members.
	lambda, err := reshareLagrangeCoeff(existingParty.Index, oldMemberIndices)
	if err != nil {
		return nil, nil, fmt.Errorf("lagrange coefficient: %w", err)
	}

	// Build polynomial: coefficients[0] = lambda * keyShare.
	coeffs := make([]group.Scalar, newThreshold)
	coeffs[0] = dkls23.ScalarMul(lambda, existingParty.KeyShare)

	// Zero the intermediate Lagrange coefficient to prevent memory residue.
	lambda.Zero()

	for i := uint8(1); i < newThreshold; i++ {
		s, err := dkls23.RandomScalar()
		if err != nil {
			return nil, nil, err
		}
		coeffs[i] = s
	}

	// Compute Feldman VSS commitments: Commitments[i] = coefficients[i] * G.
	commitments := make([]group.Point, newThreshold)
	for i, c := range coeffs {
		commitments[i] = dkls23.ScalarBaseMult(c)
	}

	// Evaluate at each new member index.
	shares := make(map[uint8]group.Scalar)
	for _, newIdx := range newMemberIndices {
		shares[newIdx] = evalPolynomialAt(coeffs, newIdx)
	}

	return &ReshareOldMemberOutput{Shares: shares, Commitments: commitments},
		&ReshareOldMemberKeep{coefficients: coeffs},
		nil
}

// ReshareNewMemberVerifyShare verifies a received sub-share from an old
// committee member using Feldman VSS. The verification checks:
//
//	share * G == sum(Commitment[i] * recipientIndex^i)
//
// This must be called for each sub-share before passing them to
// [ReshareNewMemberCollect].
func ReshareNewMemberVerifyShare(
	share group.Scalar,
	recipientIndex uint8,
	senderCommitments []group.Point,
) error {
	// LHS: share * G
	lhs := dkls23.ScalarBaseMult(share)

	// RHS: sum(Commitment[i] * recipientIndex^i) using Horner-like accumulation.
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
		return errors.New("invalid reshare sub-share from old member (Feldman VSS failed)")
	}
	return nil
}

// ReshareNewMemberCollect collects verified sub-shares from old committee
// members and sums them to produce the new key share. All sub-shares should
// be verified via [ReshareNewMemberVerifyShare] before calling this function.
//
// After calling this, continue with standard DKG Phase2 (passing the returned
// key share as the sole "fragment"), then Phase3 and Phase4 to establish
// MtA/OT correlations among the new committee.
//
// After Phase4 completes, verify that party.PublicKey matches the expected
// public key using [VerifyRefreshedPublicKey].
func ReshareNewMemberCollect(
	receivedSubShares map[uint8]group.Scalar,
	numOldMembers int,
) (group.Scalar, error) {
	if len(receivedSubShares) != numOldMembers {
		return nil, fmt.Errorf("expected %d sub-shares, got %d", numOldMembers, len(receivedSubShares))
	}

	newKeyShare := dkls23.NewScalar()
	for _, share := range receivedSubShares {
		newKeyShare = dkls23.ScalarAdd(newKeyShare, share)
	}

	// Zero received sub-shares: each contains information about
	// old members' Lagrange-weighted secret key shares.
	for key := range receivedSubShares {
		receivedSubShares[key].Zero()
	}

	return newKeyShare, nil
}

// Zero securely erases polynomial coefficients held by the old member.
func (k *ReshareOldMemberKeep) Zero() {
	if k == nil {
		return
	}
	for i := range k.coefficients {
		if k.coefficients[i] != nil {
			k.coefficients[i].Zero()
		}
	}
	k.coefficients = nil
}

// reshareLagrangeCoeff computes the Lagrange coefficient for myIndex
// within the set allIndices, evaluated at zero.
func reshareLagrangeCoeff(myIndex uint8, allIndices []uint8) (group.Scalar, error) {
	num := dkls23.NewScalar()
	// SetBytes for small integers [0,255] always succeeds (well within group order).
	num.SetBytes([]byte{1})
	den := dkls23.NewScalar()
	den.SetBytes([]byte{1})

	myScalar := dkls23.NewScalar()
	myScalar.SetBytes([]byte{myIndex})

	for _, idx := range allIndices {
		if idx == myIndex {
			continue
		}
		idxScalar := dkls23.NewScalar()
		idxScalar.SetBytes([]byte{idx})

		num = dkls23.ScalarMul(num, idxScalar)
		den = dkls23.ScalarMul(den, dkls23.ScalarSub(idxScalar, myScalar))
	}

	denInv, err := dkls23.ScalarInvert(den)
	if err != nil {
		return nil, errors.New("zero denominator (duplicate indices?)")
	}
	return dkls23.ScalarMul(num, denInv), nil
}

// evalPolynomialAt evaluates a polynomial at the given uint8 index
// using Horner's method.
func evalPolynomialAt(coeffs []group.Scalar, index uint8) group.Scalar {
	xScalar := dkls23.NewScalar()
	xScalar.SetBytes([]byte{index})

	lastIndex := len(coeffs) - 1
	result := dkls23.NewScalar().Set(coeffs[lastIndex])
	for k := lastIndex - 1; k >= 0; k-- {
		result = dkls23.ScalarAdd(dkls23.ScalarMul(result, xScalar), coeffs[k])
	}
	return result
}
