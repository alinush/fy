package golden

import (
	"github.com/f3rmion/fy/group"
)

// PadResult contains the result of an eVRF pad derivation.
type PadResult struct {
	// Pad is the derived pad as an outer-group scalar.
	Pad group.Scalar
	// RCommitment is the pad commitment: Pad * G_outer.
	RCommitment group.Point
}

// DerivePad computes the eVRF pad from a DH shared secret on the inner curve.
//
// Algorithm:
//  1. S = sk * peerPK (DH on inner curve)
//  2. Check S != identity (degenerate DH)
//  3. s = S.X (extract x-coordinate as outer-group scalar)
//  4. P1 = s_inner * H1(sessionData), where s_inner = OuterToInnerScalar(s)
//  5. P2 = s_inner * H2(sessionData)
//  6. x1 = P1.X, x2 = P2.X (both as outer-group scalars)
//  7. pad = x1 + alpha * x2 (LHL combination in outer field)
//  8. R = pad * G_outer
//
// The pad is symmetric: DerivePad(suite, sk_a, PK_b, ...) == DerivePad(suite, sk_b, PK_a, ...)
// because the DH shared secret S = sk_a * PK_b = sk_b * PK_a is the same.
func DerivePad(
	suite CurveSuite,
	sk group.Scalar,
	peerPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar, // LHL combination coefficient (outer field)
) (*PadResult, error) {
	if suite == nil {
		return nil, ErrNilSuite
	}
	innerGroup := suite.InnerGroup()
	outerGroup := suite.OuterGroup()

	// Step 1: DH shared secret on inner curve.
	S := innerGroup.NewPoint().ScalarMult(sk, peerPK)

	// Step 2: Degenerate DH check.
	if S.IsIdentity() {
		S.Zero()
		return nil, ErrDegenerateDH
	}

	// Step 3: Extract x-coordinate of S as outer-group scalar.
	s, err := suite.ExtractXAsOuterScalar(S)
	if err != nil {
		S.Zero()
		return nil, err
	}

	// Step 3b: Convert s to inner-group scalar for curve operations.
	sInner, err := suite.OuterToInnerScalar(s)
	if err != nil {
		s.Zero()
		S.Zero()
		return nil, err
	}

	// Step 4-5: Hash-to-curve and scalar multiply.
	h1Point, err := suite.H1(sessionData...)
	if err != nil {
		s.Zero()
		sInner.Zero()
		S.Zero()
		return nil, err
	}
	if h1Point.IsIdentity() {
		s.Zero()
		sInner.Zero()
		S.Zero()
		return nil, ErrIdentityPoint
	}
	h2Point, err := suite.H2(sessionData...)
	if err != nil {
		s.Zero()
		sInner.Zero()
		S.Zero()
		return nil, err
	}
	if h2Point.IsIdentity() {
		s.Zero()
		sInner.Zero()
		S.Zero()
		return nil, ErrIdentityPoint
	}

	P1 := innerGroup.NewPoint().ScalarMult(sInner, h1Point)
	P2 := innerGroup.NewPoint().ScalarMult(sInner, h2Point)

	// Zero intermediate scalar secrets.
	s.Zero()
	sInner.Zero()

	// Step 6: Extract x-coordinates.
	x1, err := suite.ExtractXAsOuterScalar(P1)
	if err != nil {
		S.Zero()
		P1.Zero()
		P2.Zero()
		return nil, err
	}
	x2, err := suite.ExtractXAsOuterScalar(P2)
	if err != nil {
		x1.Zero()
		S.Zero()
		P1.Zero()
		P2.Zero()
		return nil, err
	}

	// Zero intermediate points that held secret-derived data.
	S.Zero()
	P1.Zero()
	P2.Zero()

	// Step 7: LHL combination: pad = x1 + alpha * x2.
	alphaX2 := outerGroup.NewScalar().Mul(alpha, x2)
	pad := outerGroup.NewScalar().Add(x1, alphaX2)

	// Zero secret-derived intermediate scalars.
	x1.Zero()
	x2.Zero()
	alphaX2.Zero()

	// Step 8: Pad commitment.
	RCommitment := outerGroup.NewPoint().ScalarMult(pad, outerGroup.Generator())

	return &PadResult{
		Pad:         pad,
		RCommitment: RCommitment,
	}, nil
}
