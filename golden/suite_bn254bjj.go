package golden

import (
	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/bn254g1"
	"github.com/f3rmion/fy/group"
)

// Compile-time assertion that BN254BJJSuite implements CurveSuite.
var _ CurveSuite = (*BN254BJJSuite)(nil)

// BN254BJJSuite implements CurveSuite for the BN254/Baby JubJub curve pair.
//
// Inner group: Baby JubJub (DH, identity keys, hash-to-curve)
// Outer group: BN254 G1 (VSS commitments, pad commitments, Shamir shares)
type BN254BJJSuite struct {
	inner group.Group
	outer group.Group
}

// NewBN254BJJSuite creates a new CurveSuite for BN254/BJJ.
func NewBN254BJJSuite() *BN254BJJSuite {
	return &BN254BJJSuite{
		inner: &bjj.BJJ{},
		outer: &bn254g1.BN254G1{},
	}
}

func (s *BN254BJJSuite) InnerGroup() group.Group { return s.inner }
func (s *BN254BJJSuite) OuterGroup() group.Group { return s.outer }

func (s *BN254BJJSuite) H1(data ...[]byte) (group.Point, error) {
	return hashToCurveTryAndIncrement(h1Domain, data...)
}

func (s *BN254BJJSuite) H2(data ...[]byte) (group.Point, error) {
	return hashToCurveTryAndIncrement(h2Domain, data...)
}

func (s *BN254BJJSuite) ExtractXAsOuterScalar(innerPoint group.Point) (group.Scalar, error) {
	return extractXAsFr(s.outer, innerPoint)
}

func (s *BN254BJJSuite) OuterToInnerScalar(sc group.Scalar) (group.Scalar, error) {
	return frToBJJScalar(s.inner, sc)
}

func (s *BN254BJJSuite) GenerateEVRFProof(
	dealerSK group.Scalar,
	dealerPK, recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	padResult *PadResult,
) ([]byte, error) {
	return generateEVRFProofPLONK(dealerSK, dealerPK, recipientPK, sessionData, alpha, padResult)
}

func (s *BN254BJJSuite) VerifyEVRFProof(
	dealerPK, recipientPK group.Point,
	sessionData [][]byte,
	alpha group.Scalar,
	rCommitment group.Point,
	proofBytes []byte,
) error {
	return verifyEVRFProofPLONK(dealerPK, recipientPK, sessionData, alpha, rCommitment, proofBytes)
}
