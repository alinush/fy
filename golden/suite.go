package golden

import (
	"github.com/f3rmion/fy/group"
)

// CurveSuite abstracts the curve-pair-specific operations for the GOLDEN DKG.
//
// The DKG protocol operates across two groups:
//   - InnerGroup: the DH/identity curve (e.g., Baby JubJub)
//   - OuterGroup: the commitment/VSS curve (e.g., BN254 G1)
//
// Implementing this interface for a new curve pair allows the GOLDEN DKG
// to be used with different elliptic curve combinations without modifying
// the protocol logic.
type CurveSuite interface {
	// InnerGroup returns the DH/identity curve group (e.g., BJJ).
	InnerGroup() group.Group
	// OuterGroup returns the commitment/VSS curve group (e.g., BN254 G1).
	OuterGroup() group.Group

	// H1 hashes data to a point on the inner curve using domain 1.
	// The result must be in the prime-order subgroup.
	H1(data ...[]byte) (group.Point, error)
	// H2 hashes data to a point on the inner curve using domain 2.
	// The result must be in the prime-order subgroup.
	H2(data ...[]byte) (group.Point, error)

	// ExtractXAsOuterScalar extracts the x-coordinate of an inner-curve
	// point and interprets it as an outer-group scalar.
	ExtractXAsOuterScalar(innerPoint group.Point) (group.Scalar, error)
	// OuterToInnerScalar converts an outer-group scalar to an inner-group
	// scalar (reduction mod inner-group order).
	OuterToInnerScalar(s group.Scalar) (group.Scalar, error)

	// GenerateEVRFProof generates a ZK proof for the eVRF pad derivation.
	GenerateEVRFProof(
		dealerSK group.Scalar,
		dealerPK, recipientPK group.Point,
		sessionData [][]byte,
		alpha group.Scalar,
		padResult *PadResult,
	) ([]byte, error)

	// VerifyEVRFProof verifies a ZK proof for the eVRF pad derivation.
	VerifyEVRFProof(
		dealerPK, recipientPK group.Point,
		sessionData [][]byte,
		alpha group.Scalar,
		rCommitment group.Point,
		proofBytes []byte,
	) error
}
