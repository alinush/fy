package golden

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
)

func TestProveAndVerifyIdentity(t *testing.T) {
	g := &bjj.BJJ{}

	sk, err := g.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := g.NewPoint().ScalarMult(sk, g.Generator())

	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}

	proof, err := ProveIdentity(g, sk, pk, sid, rand.Reader)
	if err != nil {
		t.Fatalf("ProveIdentity: %v", err)
	}

	if err := VerifyIdentity(g, pk, sid, proof); err != nil {
		t.Errorf("VerifyIdentity failed: %v", err)
	}
}

func TestVerifyIdentityWrongKey(t *testing.T) {
	g := &bjj.BJJ{}

	sk, _ := g.RandomScalar(rand.Reader)
	pk := g.NewPoint().ScalarMult(sk, g.Generator())

	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}

	proof, err := ProveIdentity(g, sk, pk, sid, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with a different public key should fail.
	wrongSK, _ := g.RandomScalar(rand.Reader)
	wrongPK := g.NewPoint().ScalarMult(wrongSK, g.Generator())

	if err := VerifyIdentity(g, wrongPK, sid, proof); err == nil {
		t.Error("expected verification to fail with wrong PK")
	}
}

func TestVerifyIdentityTamperedProof(t *testing.T) {
	g := &bjj.BJJ{}

	sk, _ := g.RandomScalar(rand.Reader)
	pk := g.NewPoint().ScalarMult(sk, g.Generator())

	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}

	proof, _ := ProveIdentity(g, sk, pk, sid, rand.Reader)

	// Tamper with the response.
	one, err := scalarFromInt(g, 1)
	if err != nil {
		t.Fatal(err)
	}
	tamperedResponse := g.NewScalar().Add(proof.Response, one)

	tamperedProof := &IdentityProof{
		Commitment: proof.Commitment,
		Challenge:  proof.Challenge,
		Response:   tamperedResponse,
	}

	if err := VerifyIdentity(g, pk, sid, tamperedProof); err == nil {
		t.Error("expected verification to fail with tampered response")
	}
}
