package golden

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
	bn254g1 "github.com/f3rmion/fy/bn254g1"
)

func TestDerivePadSymmetric(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	// Generate two key pairs.
	skA, _ := bjjG.RandomScalar(rand.Reader)
	pkA := bjjG.NewPoint().ScalarMult(skA, bjjG.Generator())

	skB, _ := bjjG.RandomScalar(rand.Reader)
	pkB := bjjG.NewPoint().ScalarMult(skB, bjjG.Generator())

	// Session data and alpha.
	sessionData := [][]byte{[]byte("test-session"), []byte("round-0")}
	alpha, _ := frG.HashToScalar([]byte("golden-lhl-alpha"), []byte("test"))

	// DerivePad from A's perspective.
	padA, err := DerivePad(bjjG, frG, skA, pkB, sessionData, alpha)
	if err != nil {
		t.Fatalf("DerivePad(A->B): %v", err)
	}

	// DerivePad from B's perspective.
	padB, err := DerivePad(bjjG, frG, skB, pkA, sessionData, alpha)
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
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	skA, _ := bjjG.RandomScalar(rand.Reader)

	skB, _ := bjjG.RandomScalar(rand.Reader)
	pkB := bjjG.NewPoint().ScalarMult(skB, bjjG.Generator())

	skC, _ := bjjG.RandomScalar(rand.Reader)
	pkC := bjjG.NewPoint().ScalarMult(skC, bjjG.Generator())

	sessionData := [][]byte{[]byte("session")}
	alpha, _ := frG.HashToScalar([]byte("golden-lhl-alpha"), []byte("test"))

	padAB, _ := DerivePad(bjjG, frG, skA, pkB, sessionData, alpha)
	padAC, _ := DerivePad(bjjG, frG, skA, pkC, sessionData, alpha)

	if padAB.Pad.Equal(padAC.Pad) {
		t.Error("pads for different peers should differ")
	}
}

func TestDerivePadDifferentSessions(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	skA, _ := bjjG.RandomScalar(rand.Reader)
	skB, _ := bjjG.RandomScalar(rand.Reader)
	pkB := bjjG.NewPoint().ScalarMult(skB, bjjG.Generator())

	alpha, _ := frG.HashToScalar([]byte("golden-lhl-alpha"), []byte("test"))

	pad1, _ := DerivePad(bjjG, frG, skA, pkB, [][]byte{[]byte("session-1")}, alpha)
	pad2, _ := DerivePad(bjjG, frG, skA, pkB, [][]byte{[]byte("session-2")}, alpha)

	if pad1.Pad.Equal(pad2.Pad) {
		t.Error("pads for different sessions should differ")
	}
}

func TestDerivePadDegenerateDH(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	sk, _ := bjjG.RandomScalar(rand.Reader)
	identity := bjjG.NewPoint() // identity point

	alpha, _ := frG.HashToScalar([]byte("alpha"))

	_, err := DerivePad(bjjG, frG, sk, identity, [][]byte{[]byte("session")}, alpha)
	if err != ErrDegenerateDH {
		t.Errorf("expected ErrDegenerateDH, got %v", err)
	}
}

func TestDerivePadRCommitmentConsistent(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	skA, _ := bjjG.RandomScalar(rand.Reader)
	skB, _ := bjjG.RandomScalar(rand.Reader)
	pkB := bjjG.NewPoint().ScalarMult(skB, bjjG.Generator())

	alpha, _ := frG.HashToScalar([]byte("golden-lhl-alpha"), []byte("test"))
	sessionData := [][]byte{[]byte("session")}

	result, err := DerivePad(bjjG, frG, skA, pkB, sessionData, alpha)
	if err != nil {
		t.Fatal(err)
	}

	// Verify R = pad * G_bn254.
	expectedR := frG.NewPoint().ScalarMult(result.Pad, frG.Generator())
	if !result.RCommitment.Equal(expectedR) {
		t.Error("R commitment is not pad * G")
	}
}
