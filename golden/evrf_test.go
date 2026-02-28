package golden

import (
	"crypto/rand"
	"testing"
)

func TestDerivePadSymmetric(t *testing.T) {
	suite := NewBN254BJJSuite()
	innerG := suite.InnerGroup()
	outerG := suite.OuterGroup()

	// Generate two key pairs.
	skA, _ := innerG.RandomScalar(rand.Reader)
	pkA := innerG.NewPoint().ScalarMult(skA, innerG.Generator())

	skB, _ := innerG.RandomScalar(rand.Reader)
	pkB := innerG.NewPoint().ScalarMult(skB, innerG.Generator())

	// Session data and alpha.
	sessionData := [][]byte{[]byte("test-session"), []byte("round-0")}
	alpha, _ := outerG.HashToScalar([]byte(lhlAlphaDomain), []byte("test"))

	// DerivePad from A's perspective.
	padA, err := DerivePad(suite, skA, pkB, sessionData, alpha)
	if err != nil {
		t.Fatalf("DerivePad(A->B): %v", err)
	}

	// DerivePad from B's perspective.
	padB, err := DerivePad(suite, skB, pkA, sessionData, alpha)
	if err != nil {
		t.Fatalf("DerivePad(B->A): %v", err)
	}

	// Pads must be equal (symmetric DH).
	if !padA.Pad.Equal(padB.Pad) {
		t.Error("pads are not symmetric")
	}

	// R commitments must also be equal.
	if !padA.RCommitment.Equal(padB.RCommitment) {
		t.Error("R commitments are not symmetric")
	}
}

func TestDerivePadDifferentPeers(t *testing.T) {
	suite := NewBN254BJJSuite()
	innerG := suite.InnerGroup()
	outerG := suite.OuterGroup()

	skA, _ := innerG.RandomScalar(rand.Reader)

	skB, _ := innerG.RandomScalar(rand.Reader)
	pkB := innerG.NewPoint().ScalarMult(skB, innerG.Generator())

	skC, _ := innerG.RandomScalar(rand.Reader)
	pkC := innerG.NewPoint().ScalarMult(skC, innerG.Generator())

	sessionData := [][]byte{[]byte("session")}
	alpha, _ := outerG.HashToScalar([]byte(lhlAlphaDomain), []byte("test"))

	padAB, _ := DerivePad(suite, skA, pkB, sessionData, alpha)
	padAC, _ := DerivePad(suite, skA, pkC, sessionData, alpha)

	if padAB.Pad.Equal(padAC.Pad) {
		t.Error("pads for different peers should differ")
	}
}

func TestDerivePadDifferentSessions(t *testing.T) {
	suite := NewBN254BJJSuite()
	innerG := suite.InnerGroup()
	outerG := suite.OuterGroup()

	skA, _ := innerG.RandomScalar(rand.Reader)
	skB, _ := innerG.RandomScalar(rand.Reader)
	pkB := innerG.NewPoint().ScalarMult(skB, innerG.Generator())

	alpha, _ := outerG.HashToScalar([]byte(lhlAlphaDomain), []byte("test"))

	pad1, _ := DerivePad(suite, skA, pkB, [][]byte{[]byte("session-1")}, alpha)
	pad2, _ := DerivePad(suite, skA, pkB, [][]byte{[]byte("session-2")}, alpha)

	if pad1.Pad.Equal(pad2.Pad) {
		t.Error("pads for different sessions should differ")
	}
}

func TestDerivePadDegenerateDH(t *testing.T) {
	suite := NewBN254BJJSuite()
	innerG := suite.InnerGroup()
	outerG := suite.OuterGroup()

	sk, _ := innerG.RandomScalar(rand.Reader)
	identity := innerG.NewPoint() // identity point

	alpha, _ := outerG.HashToScalar([]byte("alpha"))

	_, err := DerivePad(suite, sk, identity, [][]byte{[]byte("session")}, alpha)
	if err != ErrDegenerateDH {
		t.Errorf("expected ErrDegenerateDH, got %v", err)
	}
}

func TestDerivePadRCommitmentConsistent(t *testing.T) {
	suite := NewBN254BJJSuite()
	innerG := suite.InnerGroup()
	outerG := suite.OuterGroup()

	skA, _ := innerG.RandomScalar(rand.Reader)
	skB, _ := innerG.RandomScalar(rand.Reader)
	pkB := innerG.NewPoint().ScalarMult(skB, innerG.Generator())

	alpha, _ := outerG.HashToScalar([]byte(lhlAlphaDomain), []byte("test"))
	sessionData := [][]byte{[]byte("session")}

	result, err := DerivePad(suite, skA, pkB, sessionData, alpha)
	if err != nil {
		t.Fatal(err)
	}

	// Verify R = pad * G_bn254.
	expectedR := outerG.NewPoint().ScalarMult(result.Pad, outerG.Generator())
	if !result.RCommitment.Equal(expectedR) {
		t.Error("R commitment is not pad * G")
	}
}
