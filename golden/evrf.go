package golden

import (
	"github.com/f3rmion/fy/group"
)

// PadResult contains the result of an eVRF pad derivation.
type PadResult struct {
	// Pad is the derived pad as a BN254 Fr scalar.
	Pad group.Scalar
	// RCommitment is the pad commitment: Pad * G_bn254.
	RCommitment group.Point
}

// DerivePad computes the eVRF pad from a DH shared secret on BJJ.
//
// Algorithm:
//  1. S = sk * peerPK (DH on BJJ)
//  2. Check S != identity (degenerate DH)
//  3. s = S.X (extract x-coordinate, which is a BN254 Fr element natively)
//  4. P1 = s_bjj * H1(sessionData) on BJJ, where s_bjj = frToBJJScalar(s)
//  5. P2 = s_bjj * H2(sessionData) on BJJ
//  6. x1 = P1.X, x2 = P2.X (both in Fr natively)
//  7. pad = x1 + alpha * x2 in Fr (LHL combination)
//  8. R = pad * G_bn254
//
// The frToBJJScalar reduction (mod l) at step 4 is algebraically equivalent to
// using s directly as a scalar on BJJ subgroup points, since [s]H = [s mod l]H
// for any point H of order l. The reduction is needed because the BJJ group.Scalar
// type expects values in [0, l).
//
// The pad is symmetric: DerivePad(sk_a, PK_b, ...) == DerivePad(sk_b, PK_a, ...)
// because the DH shared secret S = sk_a * PK_b = sk_b * PK_a is the same.
func DerivePad(
	bjjGroup group.Group,
	bn254Group group.Group,
	sk group.Scalar,
	peerPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar, // LHL combination coefficient (Fr)
) (*PadResult, error) {
	// Step 1: DH shared secret on BJJ.
	S := bjjGroup.NewPoint().ScalarMult(sk, peerPK)

	// Step 2: Degenerate DH check.
	if S.IsIdentity() {
		return nil, ErrDegenerateDH
	}

	// Step 3: Extract x-coordinate of S as Fr element.
	// BJJ coordinates are in BN254 Fr (base field = scalar field), so this is native.
	s, err := extractXAsFr(bn254Group, S)
	if err != nil {
		return nil, err
	}

	// Step 3b: Convert s to BJJ scalar for curve operations.
	sBJJ, err := frToBJJScalar(bjjGroup, s)
	if err != nil {
		return nil, err
	}

	// Step 4-5: Hash-to-curve and scalar multiply.
	h1Point, err := H1(bjjGroup, sessionData...)
	if err != nil {
		return nil, err
	}
	h2Point, err := H2(bjjGroup, sessionData...)
	if err != nil {
		return nil, err
	}

	P1 := bjjGroup.NewPoint().ScalarMult(sBJJ, h1Point)
	P2 := bjjGroup.NewPoint().ScalarMult(sBJJ, h2Point)

	// Zero intermediate secrets.
	s.Zero()
	sBJJ.Zero()

	// Step 6: Extract x-coordinates.
	x1, err := extractXAsFr(bn254Group, P1)
	if err != nil {
		return nil, err
	}
	x2, err := extractXAsFr(bn254Group, P2)
	if err != nil {
		return nil, err
	}

	// Step 7: LHL combination: pad = x1 + alpha * x2.
	alphaX2 := bn254Group.NewScalar().Mul(alpha, x2)
	pad := bn254Group.NewScalar().Add(x1, alphaX2)

	// Step 8: Pad commitment.
	RCommitment := bn254Group.NewPoint().ScalarMult(pad, bn254Group.Generator())

	return &PadResult{
		Pad:         pad,
		RCommitment: RCommitment,
	}, nil
}
