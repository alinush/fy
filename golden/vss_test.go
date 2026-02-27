package golden

import (
	"crypto/rand"
	"testing"

	bn254g1 "github.com/f3rmion/fy/bn254g1"
)

func TestVSSCommitAndVerify(t *testing.T) {
	g := &bn254g1.BN254G1{}

	// Polynomial and shares are all in Fr (same field as VSS commitments).
	secret, _ := g.RandomScalar(rand.Reader)
	poly, err := NewRandomPolynomial(g, secret, 2, rand.Reader) // degree 2, threshold 3
	if err != nil {
		t.Fatal(err)
	}

	// Generate VSS commitments (A_k = a_k * G, all in Fr).
	commitments, err := VSSCommit(g, poly)
	if err != nil {
		t.Fatalf("VSSCommit: %v", err)
	}

	if len(commitments) != 3 {
		t.Fatalf("expected 3 commitments, got %d", len(commitments))
	}

	// Generate shares and verify each against VSS commitments.
	n := 5
	shares := GenerateShares(g, poly, n)

	for i := 1; i <= n; i++ {
		share := shares[i]

		// share * G should equal ExpectedShareCommitment.
		shareCommit := g.NewPoint().ScalarMult(share, g.Generator())
		expected := ExpectedShareCommitment(g, commitments, i)

		if !shareCommit.Equal(expected) {
			t.Errorf("share %d: commitment mismatch", i)
		}
	}
}

func TestVSSTamperedShareRejected(t *testing.T) {
	g := &bn254g1.BN254G1{}

	secret, _ := g.RandomScalar(rand.Reader)
	poly, _ := NewRandomPolynomial(g, secret, 1, rand.Reader) // degree 1

	commitments, err := VSSCommit(g, poly)
	if err != nil {
		t.Fatal(err)
	}

	shares := GenerateShares(g, poly, 3)

	// Tamper with share 1.
	one := scalarFromInt(g, 1)
	tamperedShare := g.NewScalar().Add(shares[1], one)

	tamperedCommit := g.NewPoint().ScalarMult(tamperedShare, g.Generator())
	expected := ExpectedShareCommitment(g, commitments, 1)

	if tamperedCommit.Equal(expected) {
		t.Error("tampered share should not match VSS commitment")
	}
}
