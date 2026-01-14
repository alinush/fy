package railgun

import (
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// bigIntTo32Bytes pads or truncates a big.Int to 32 bytes
func bigIntTo32Bytes(b *big.Int) []byte {
	bytes := b.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

// TestVerifyUnshieldSignature verifies the signature from the failed unshield attempt
func TestVerifyUnshieldSignature(t *testing.T) {
	// Values from the latest unshield debug output
	ax, _ := new(big.Int).SetString("19903188943442933916647838691607817468325654974083956392197348841280345610540", 10)
	ay, _ := new(big.Int).SetString("9182836975774781391674077818289149487299667203599347036719377596456676332396", 10)
	rx, _ := new(big.Int).SetString("2844469737519446714966955519949462876132028123032202831671332452807443668436", 10)
	ry, _ := new(big.Int).SetString("3976496458234181738508283841431247783419904337334875864937484750553262568140", 10)
	s, _ := new(big.Int).SetString("1136164551451071834004093385547520675420254849008849574747412929794656903823", 10)
	msgHash, _ := new(big.Int).SetString("10534927528885338069959055783799728009936301001769134292762243022375620655231", 10)

	t.Log("=== Signature Verification ===")
	t.Logf("A.x: %s", ax.String())
	t.Logf("A.y: %s", ay.String())
	t.Logf("R.x: %s", rx.String())
	t.Logf("R.y: %s", ry.String())
	t.Logf("S: %s", s.String())
	t.Logf("msg: %s", msgHash.String())

	g := bjj.NewCircomBJJ()

	// Create A point from x,y
	aBytes := append(bigIntTo32Bytes(ax), bigIntTo32Bytes(ay)...)
	A := g.NewPoint().(*bjj.CircomPoint)
	if _, err := A.SetUncompressedBytes(aBytes); err != nil {
		t.Fatalf("A not on curve: %v", err)
	}
	t.Log("\nA on curve: true")

	// Create R point from x,y
	rBytes := append(bigIntTo32Bytes(rx), bigIntTo32Bytes(ry)...)
	R := g.NewPoint().(*bjj.CircomPoint)
	if _, err := R.SetUncompressedBytes(rBytes); err != nil {
		t.Fatalf("R not on curve: %v", err)
	}
	t.Log("R on curve: true")

	Base8 := g.Generator().(*bjj.CircomPoint)
	base8Unc := Base8.UncompressedBytes()
	base8X := new(big.Int).SetBytes(base8Unc[:32])
	base8Y := new(big.Int).SetBytes(base8Unc[32:])
	t.Logf("Base8: (%s, %s)", base8X.String(), base8Y.String())

	// Compute challenge: c = poseidon([R.x, R.y, A.x, A.y, msg])
	c, err := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msgHash})
	if err != nil {
		t.Fatalf("Error computing challenge: %v", err)
	}
	t.Logf("\nChallenge c: %s", c.String())

	// SubOrder for scalar operations
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	// LHS = S * Base8
	sScalar := g.NewScalar()
	sScalar.SetBytes(s.Bytes())
	LHS := g.NewPoint().ScalarMult(sScalar, Base8).(*bjj.CircomPoint)
	lhsUnc := LHS.UncompressedBytes()
	lhsX := new(big.Int).SetBytes(lhsUnc[:32])
	lhsY := new(big.Int).SetBytes(lhsUnc[32:])
	t.Logf("\nLHS (S * Base8):\n  X: %s\n  Y: %s", lhsX.String(), lhsY.String())

	// c8 = c * 8 mod subOrder
	c8 := new(big.Int).Mul(c, big.NewInt(8))
	c8.Mod(c8, subOrder)
	t.Logf("\nc * 8 mod subOrder: %s", c8.String())

	// c8 * A
	c8Scalar := g.NewScalar()
	c8Scalar.SetBytes(c8.Bytes())
	c8A := g.NewPoint().ScalarMult(c8Scalar, A).(*bjj.CircomPoint)
	c8aUnc := c8A.UncompressedBytes()
	c8aX := new(big.Int).SetBytes(c8aUnc[:32])
	c8aY := new(big.Int).SetBytes(c8aUnc[32:])
	t.Logf("\nc*8*A:\n  X: %s\n  Y: %s", c8aX.String(), c8aY.String())

	// RHS = R + c8*A
	RHS := g.NewPoint().Add(R, c8A).(*bjj.CircomPoint)
	rhsUnc := RHS.UncompressedBytes()
	rhsX := new(big.Int).SetBytes(rhsUnc[:32])
	rhsY := new(big.Int).SetBytes(rhsUnc[32:])
	t.Logf("\nRHS (R + c*8*A):\n  X: %s\n  Y: %s", rhsX.String(), rhsY.String())

	// Check equality
	t.Log("\n=== VERIFICATION ===")
	t.Logf("LHS.X == RHS.X: %v", lhsX.Cmp(rhsX) == 0)
	t.Logf("LHS.Y == RHS.Y: %v", lhsY.Cmp(rhsY) == 0)

	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("\n✓ SIGNATURE VALID!")
	} else {
		t.Error("\n✗ SIGNATURE INVALID!")
	}
}
