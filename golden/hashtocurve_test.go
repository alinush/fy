package golden

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/f3rmion/fy/bjj"
)

func TestH1OnCurveAndSubgroup(t *testing.T) {
	suite := NewBN254BJJSuite()
	data := []byte("test-input-h1")

	p, err := suite.H1(data)
	if err != nil {
		t.Fatalf("H1 failed: %v", err)
	}
	if p == nil {
		t.Fatal("H1 returned nil point")
	}
	if p.IsIdentity() {
		t.Error("H1 returned the identity point")
	}

	// Verify subgroup membership via serialization round-trip.
	encoded := p.Bytes()
	restored := suite.InnerGroup().NewPoint()
	if _, err := restored.SetBytes(encoded); err != nil {
		t.Errorf("H1 result failed subgroup/on-curve check via SetBytes: %v", err)
	}

	// Also verify using the IsInSubgroup method directly.
	bp := p.(*bjj.Point)
	if !bp.IsInSubgroup() {
		t.Error("H1 result is not in the prime-order subgroup")
	}
}

func TestH2OnCurveAndSubgroup(t *testing.T) {
	suite := NewBN254BJJSuite()
	data := []byte("test-input-h2")

	p, err := suite.H2(data)
	if err != nil {
		t.Fatalf("H2 failed: %v", err)
	}
	if p == nil {
		t.Fatal("H2 returned nil point")
	}
	if p.IsIdentity() {
		t.Error("H2 returned the identity point")
	}

	encoded := p.Bytes()
	restored := suite.InnerGroup().NewPoint()
	if _, err := restored.SetBytes(encoded); err != nil {
		t.Errorf("H2 result failed subgroup/on-curve check via SetBytes: %v", err)
	}

	bp := p.(*bjj.Point)
	if !bp.IsInSubgroup() {
		t.Error("H2 result is not in the prime-order subgroup")
	}
}

func TestH1Deterministic(t *testing.T) {
	suite := NewBN254BJJSuite()
	data := []byte("deterministic-test-input")

	p1, err := suite.H1(data)
	if err != nil {
		t.Fatalf("H1 first call failed: %v", err)
	}

	p2, err := suite.H1(data)
	if err != nil {
		t.Fatalf("H1 second call failed: %v", err)
	}

	if !p1.Equal(p2) {
		t.Error("H1 is not deterministic: same input produced different outputs")
	}
}

func TestH1H2DomainSeparation(t *testing.T) {
	suite := NewBN254BJJSuite()
	data := []byte("domain-separation-test")

	p1, err := suite.H1(data)
	if err != nil {
		t.Fatalf("H1 failed: %v", err)
	}

	p2, err := suite.H2(data)
	if err != nil {
		t.Fatalf("H2 failed: %v", err)
	}

	if p1.Equal(p2) {
		t.Error("H1 and H2 produced the same output for the same input; domain separation failed")
	}
}

func TestH1DifferentInputs(t *testing.T) {
	suite := NewBN254BJJSuite()

	p1, err := suite.H1([]byte("input-alpha"))
	if err != nil {
		t.Fatalf("H1(input-alpha) failed: %v", err)
	}

	p2, err := suite.H1([]byte("input-beta"))
	if err != nil {
		t.Fatalf("H1(input-beta) failed: %v", err)
	}

	if p1.Equal(p2) {
		t.Error("H1 produced the same output for different inputs")
	}
}

func TestH1MultipleDataArgs(t *testing.T) {
	suite := NewBN254BJJSuite()

	p1, err := suite.H1([]byte("part1"), []byte("part2"))
	if err != nil {
		t.Fatalf("H1(part1, part2) failed: %v", err)
	}

	p2, err := suite.H1([]byte("part1part2"))
	if err != nil {
		t.Fatalf("H1(part1part2) failed: %v", err)
	}

	if p1.Equal(p2) {
		t.Error("H1(a, b) == H1(a||b); length-prefix domain separation failed")
	}

	// Verify both are valid subgroup points.
	bp1 := p1.(*bjj.Point)
	bp2 := p2.(*bjj.Point)
	if !bp1.IsInSubgroup() {
		t.Error("H1(part1, part2) not in subgroup")
	}
	if !bp2.IsInSubgroup() {
		t.Error("H1(part1part2) not in subgroup")
	}
}

func TestH1CofactorClearing(t *testing.T) {
	suite := NewBN254BJJSuite()
	g := suite.InnerGroup()
	data := []byte("cofactor-test")

	p, err := suite.H1(data)
	if err != nil {
		t.Fatalf("H1 failed: %v", err)
	}

	// Multiplying by the subgroup order should give the identity.
	curve := twistededwards.GetEdwardsCurve()
	order := new(big.Int).Set(&curve.Order)

	check := g.NewPoint().ScalarMult(
		mustScalarFromBigInt(g.(*bjj.BJJ), order),
		p,
	)
	if !check.IsIdentity() {
		t.Error("order * H1(data) != identity; point not in subgroup")
	}
}

// mustScalarFromBigInt creates a bjj scalar from a big.Int for testing.
func mustScalarFromBigInt(g *bjj.BJJ, n *big.Int) *bjj.Scalar {
	s := g.NewScalar().(*bjj.Scalar)
	if _, err := s.SetBytes(n.Bytes()); err != nil {
		panic(err)
	}
	return s
}
