package railgun

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
	"github.com/f3rmion/fy/session"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestFullSigningCycle tests a complete FROST signing cycle with CircomBJJ
func TestFullSigningCycle(t *testing.T) {
	// Create FROST instance with CircomBJJ and RailgunHasher
	g := bjj.NewCircomBJJ()
	f, err := frost.NewWithHasher(g, 2, 2, frost.NewRailgunHasher())
	if err != nil {
		t.Fatalf("Failed to create FROST: %v", err)
	}

	// Run DKG
	t.Log("Running DKG...")
	p1, _ := f.NewParticipant(rand.Reader, 1)
	p2, _ := f.NewParticipant(rand.Reader, 2)

	broadcasts := []*frost.Round1Data{
		p1.Round1Broadcast(),
		p2.Round1Broadcast(),
	}

	// Exchange private shares
	ps1to2 := f.Round1PrivateSend(p1, 2)
	ps2to1 := f.Round1PrivateSend(p2, 1)
	f.Round2ReceiveShare(p1, ps2to1, broadcasts[1].Commitments)
	f.Round2ReceiveShare(p2, ps1to2, broadcasts[0].Commitments)

	// Finalize
	ks1, _ := f.Finalize(p1, broadcasts)
	ks2, _ := f.Finalize(p2, broadcasts)

	// Verify group keys match
	if !ks1.GroupKey.Equal(ks2.GroupKey) {
		t.Fatal("Group keys don't match!")
	}
	t.Log("DKG complete, group keys match")

	// Get Y and A
	yPoint := ks1.GroupKey.(*bjj.CircomPoint)
	yUnc := yPoint.UncompressedBytes()
	yx := new(big.Int).SetBytes(yUnc[:32])
	yy := new(big.Int).SetBytes(yUnc[32:])
	t.Logf("Group key Y: (%s, %s)", yx.String(), yy.String())

	aPoint := yPoint.DivBy8()
	aUnc := aPoint.UncompressedBytes()
	ax := new(big.Int).SetBytes(aUnc[:32])
	ay := new(big.Int).SetBytes(aUnc[32:])
	t.Logf("Public key A (Y/8): (%s, %s)", ax.String(), ay.String())

	// Create message hash (like Railgun does)
	merkleRoot := big.NewInt(12345)
	boundParamsHash := big.NewInt(67890)
	nullifier := big.NewInt(11111)
	commitment1 := big.NewInt(22222)
	commitment2 := big.NewInt(33333)
	msgHash, _ := poseidon.Hash([]*big.Int{merkleRoot, boundParamsHash, nullifier, commitment1, commitment2})
	t.Logf("Message hash: %s", msgHash.String())

	// Sign using session package (like the daemon does)
	t.Log("Signing...")
	sp1, _ := session.NewParticipantWithHasher(g, 2, 2, 1, frost.NewRailgunHasher())
	if err := sp1.SetKeyShare(ks1); err != nil {
		t.Fatalf("failed to set key share for sp1: %v", err)
	}
	sp2, _ := session.NewParticipantWithHasher(g, 2, 2, 2, frost.NewRailgunHasher())
	if err := sp2.SetKeyShare(ks2); err != nil {
		t.Fatalf("failed to set key share for sp2: %v", err)
	}

	sess1, _ := sp1.NewSigningSession(rand.Reader, msgHash.Bytes())
	sess2, _ := sp2.NewSigningSession(rand.Reader, msgHash.Bytes())

	commitments := []*frost.SigningCommitment{
		sess1.Commitment(),
		sess2.Commitment(),
	}

	share1, _ := sess1.Sign(commitments)
	share2, _ := sess2.Sign(commitments)

	shares := []*frost.SignatureShare{share1, share2}

	sig, err := session.Aggregate(f, msgHash.Bytes(), commitments, shares)
	if err != nil {
		t.Fatalf("Aggregation failed: %v", err)
	}

	// Get signature components
	rPoint := sig.R.(*bjj.CircomPoint)
	rUnc := rPoint.UncompressedBytes()
	rx := new(big.Int).SetBytes(rUnc[:32])
	ry := new(big.Int).SetBytes(rUnc[32:])
	sScalar := sig.Z
	sBytes := sScalar.Bytes()
	s := new(big.Int).SetBytes(sBytes)
	t.Logf("Signature R: (%s, %s)", rx.String(), ry.String())
	t.Logf("Signature S: %s", s.String())

	// Verify using FROST.Verify (with group key Y)
	t.Log("Verifying with FROST.Verify...")
	if f.Verify(msgHash.Bytes(), sig, yPoint) {
		t.Log("FROST.Verify: PASSED")
	} else {
		t.Error("FROST.Verify: FAILED")
	}

	// Also verify manually using circomlibjs equation
	t.Log("Manual verification using circomlibjs equation...")

	base8 := g.Generator().(*bjj.CircomPoint)

	// LHS: S * Base8
	lhs := g.NewPoint().ScalarMult(sScalar, base8).(*bjj.CircomPoint)
	lhsUnc := lhs.UncompressedBytes()
	lhsX := new(big.Int).SetBytes(lhsUnc[:32])
	lhsY := new(big.Int).SetBytes(lhsUnc[32:])
	t.Logf("LHS (S * Base8): (%s, %s)", lhsX.String(), lhsY.String())

	// Compute challenge c = poseidon([R.x, R.y, A.x, A.y, msg])
	challenge, _ := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msgHash})
	t.Logf("Challenge c: %s", challenge.String())

	// c * 8
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	c8 := new(big.Int).Mul(challenge, big.NewInt(8))
	c8.Mod(c8, subOrder)
	c8Scalar := g.NewScalar()
	c8Scalar.SetBytes(c8.Bytes())

	// (c * 8) * A
	c8A := g.NewPoint().ScalarMult(c8Scalar, aPoint).(*bjj.CircomPoint)

	// RHS: R + (c * 8) * A
	rhs := g.NewPoint().Add(rPoint, c8A).(*bjj.CircomPoint)
	rhsUnc := rhs.UncompressedBytes()
	rhsX := new(big.Int).SetBytes(rhsUnc[:32])
	rhsY := new(big.Int).SetBytes(rhsUnc[32:])
	t.Logf("RHS (R + c*8*A): (%s, %s)", rhsX.String(), rhsY.String())

	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("Manual circomlibjs verification: PASSED")
	} else {
		t.Error("Manual circomlibjs verification: FAILED")
	}
}
