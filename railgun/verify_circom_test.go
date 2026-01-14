package railgun

import (
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestVerifyWithCircomBJJ verifies the signature using actual CircomBJJ group operations
func TestVerifyWithCircomBJJ(t *testing.T) {
	// Actual values from the failing unshield
	ax, _ := new(big.Int).SetString("20026889608777403795665626800907346608158208569402487973918721176355059291675", 10)
	ay, _ := new(big.Int).SetString("13200796977118599908275481645910090925733298062348995995426837734696675042566", 10)

	rx, _ := new(big.Int).SetString("19305565585201351841753416215756429401666555254609991991707505851312759774864", 10)
	ry, _ := new(big.Int).SetString("21282012280664667577405162615843447752666302418672774231131397311175112635230", 10)
	s, _ := new(big.Int).SetString("1297527204203028169718415960767588314192185288215579339133960283402655473001", 10)

	msgHash, _ := new(big.Int).SetString("5490089411662003245665387211891846584887876999214360353985710394781499540523", 10)

	// Create CircomBJJ group
	g := bjj.NewCircomBJJ()

	// Get Base8 generator
	base8 := g.Generator().(*bjj.CircomPoint)
	t.Logf("Base8: (%s, %s)", base8.UncompressedBytes()[:32], base8.UncompressedBytes()[32:])

	// Reconstruct points
	aBytes := make([]byte, 64)
	copy(aBytes[32-len(ax.Bytes()):32], ax.Bytes())
	copy(aBytes[64-len(ay.Bytes()):64], ay.Bytes())
	aPoint := g.NewPoint().(*bjj.CircomPoint)
	if _, err := aPoint.SetUncompressedBytes(aBytes); err != nil {
		t.Fatalf("Failed to set A point: %v", err)
	}
	t.Logf("A point valid: (%s, %s)", ax.String(), ay.String())

	rBytes := make([]byte, 64)
	copy(rBytes[32-len(rx.Bytes()):32], rx.Bytes())
	copy(rBytes[64-len(ry.Bytes()):64], ry.Bytes())
	rPoint := g.NewPoint().(*bjj.CircomPoint)
	if _, err := rPoint.SetUncompressedBytes(rBytes); err != nil {
		t.Fatalf("Failed to set R point: %v", err)
	}
	t.Logf("R point valid: (%s, %s)", rx.String(), ry.String())

	// Compute Y = 8 * A (the FROST group key)
	eight := g.NewScalar()
	eight.SetBytes(big.NewInt(8).Bytes())
	yPoint := g.NewPoint().ScalarMult(eight, aPoint).(*bjj.CircomPoint)
	yUnc := yPoint.UncompressedBytes()
	yx := new(big.Int).SetBytes(yUnc[:32])
	yy := new(big.Int).SetBytes(yUnc[32:])
	t.Logf("Y = 8*A: (%s, %s)", yx.String(), yy.String())

	// Create scalar from S
	sScalar := g.NewScalar()
	sScalar.SetBytes(s.Bytes())

	// Compute LHS: S * Base8
	lhs := g.NewPoint().ScalarMult(sScalar, base8).(*bjj.CircomPoint)
	lhsUnc := lhs.UncompressedBytes()
	lhsX := new(big.Int).SetBytes(lhsUnc[:32])
	lhsY := new(big.Int).SetBytes(lhsUnc[32:])
	t.Logf("LHS (S * Base8): (%s, %s)", lhsX.String(), lhsY.String())

	// Compute challenge c = poseidon([R.x, R.y, A.x, A.y, msg])
	challenge, _ := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msgHash})
	t.Logf("Challenge c: %s", challenge.String())

	// Compute c * 8
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	c8 := new(big.Int).Mul(challenge, big.NewInt(8))
	c8.Mod(c8, subOrder)
	c8Scalar := g.NewScalar()
	c8Scalar.SetBytes(c8.Bytes())

	// Compute (c * 8) * A
	c8A := g.NewPoint().ScalarMult(c8Scalar, aPoint).(*bjj.CircomPoint)

	// Compute RHS: R + (c * 8) * A
	rhs := g.NewPoint().Add(rPoint, c8A).(*bjj.CircomPoint)
	rhsUnc := rhs.UncompressedBytes()
	rhsX := new(big.Int).SetBytes(rhsUnc[:32])
	rhsY := new(big.Int).SetBytes(rhsUnc[32:])
	t.Logf("RHS (R + c*8*A): (%s, %s)", rhsX.String(), rhsY.String())

	// Check if they match
	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("SUCCESS: S * Base8 = R + (c * 8) * A")
	} else {
		t.Error("FAILED: S * Base8 != R + (c * 8) * A")

		// Try the alternative: S * Base8 = R + c * Y
		cScalar := g.NewScalar()
		cScalar.SetBytes(challenge.Bytes())
		cY := g.NewPoint().ScalarMult(cScalar, yPoint).(*bjj.CircomPoint)
		altRhs := g.NewPoint().Add(rPoint, cY).(*bjj.CircomPoint)
		altRhsUnc := altRhs.UncompressedBytes()
		altRhsX := new(big.Int).SetBytes(altRhsUnc[:32])
		altRhsY := new(big.Int).SetBytes(altRhsUnc[32:])
		t.Logf("Alt RHS (R + c*Y): (%s, %s)", altRhsX.String(), altRhsY.String())

		if lhsX.Cmp(altRhsX) == 0 && lhsY.Cmp(altRhsY) == 0 {
			t.Log("SUCCESS with alternative: S * Base8 = R + c * Y")
		}
	}

	// Also verify using FROST's built-in verification
	t.Log("\n=== Testing FROST.Verify ===")
	frostInstance, _ := frost.NewWithHasher(g, 2, 2, frost.NewRailgunHasher())

	frostSig := &frost.Signature{
		R: rPoint,
		Z: sScalar,
	}

	// FROST.Verify uses the GROUP KEY Y, not A
	if frostInstance.Verify(msgHash.Bytes(), frostSig, yPoint) {
		t.Log("FROST.Verify with Y: PASSED")
	} else {
		t.Log("FROST.Verify with Y: FAILED")
	}

	// Try verifying with A
	if frostInstance.Verify(msgHash.Bytes(), frostSig, aPoint) {
		t.Log("FROST.Verify with A: PASSED")
	} else {
		t.Log("FROST.Verify with A: FAILED")
	}
}
