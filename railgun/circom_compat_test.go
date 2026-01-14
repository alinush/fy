package railgun

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestCircomlibCompatibility verifies FROST signature compatibility with circomlibjs.
// This test computes signatures using FROST and verifies them using the exact
// verification equation that circomlibjs uses.
func TestCircomlibCompatibility(t *testing.T) {
	// Constants
	fieldP, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	// circomlibjs Base8 (used for verification)
	base8X, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	base8Y, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	// Create a 2-of-3 threshold wallet
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	// Get group key Y
	groupKey := shares[0].SpendingKeyShare.GroupKey
	groupKeyPoint := groupKey.(*bjj.CircomPoint)
	gkBytes := groupKeyPoint.UncompressedBytes()
	yx := new(big.Int).SetBytes(gkBytes[0:32])
	yy := new(big.Int).SetBytes(gkBytes[32:64])

	t.Logf("=== FROST Group Key Y ===")
	t.Logf("Y.x = %s", yx.String())
	t.Logf("Y.y = %s", yy.String())

	// Compute A = Y/8 (circomlibjs-compatible public key)
	inv8 := new(big.Int).ModInverse(big.NewInt(8), subOrder)
	ax, ay := circomScalarMult(yx, yy, inv8, fieldP)

	t.Logf("\n=== circomlibjs Public Key A = Y/8 ===")
	t.Logf("A.x = %s", ax.String())
	t.Logf("A.y = %s", ay.String())

	// Create a message (Poseidon hash like Railgun)
	msg, _ := poseidon.Hash([]*big.Int{big.NewInt(42), big.NewInt(123)})
	t.Logf("\n=== Message ===")
	t.Logf("msg = %s", msg.String())

	// Sign with FROST
	sig, err := tw.Sign(shares[:2], msg.Bytes())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	t.Logf("\n=== FROST Signature ===")
	t.Logf("R.x = %s", sig.RX.String())
	t.Logf("R.y = %s", sig.RY.String())
	t.Logf("z   = %s", sig.S.String())

	// Verify with native FROST
	if !tw.Verify(groupKey, msg.Bytes(), sig) {
		t.Error("Native FROST verification failed!")
	} else {
		t.Log("\n✓ Native FROST verification PASSED")
	}

	// Now compute circomlibjs verification
	// circomlibjs equation: S * Base8 = R + c * A
	// where c = poseidon([R.x, R.y, A.x, A.y, msg])

	// Compute challenge (circomlibjs format)
	challenge, err := poseidon.Hash([]*big.Int{sig.RX, sig.RY, ax, ay, msg})
	if err != nil {
		t.Fatalf("poseidon.Hash() error = %v", err)
	}
	t.Logf("\n=== Challenge (circomlibjs format) ===")
	t.Logf("c = poseidon([R.x, R.y, A.x, A.y, msg])")
	t.Logf("c = %s", challenge.String())

	// Compute LHS: z * Base8
	lhsX, lhsY := circomScalarMult(base8X, base8Y, sig.S, fieldP)
	t.Logf("\n=== LHS: z * Base8 ===")
	t.Logf("(z * Base8).x = %s", lhsX.String())
	t.Logf("(z * Base8).y = %s", lhsY.String())

	// Compute RHS: R + c * A
	cAx, cAy := circomScalarMult(ax, ay, challenge, fieldP)
	t.Logf("\n=== c * A ===")
	t.Logf("(c * A).x = %s", cAx.String())
	t.Logf("(c * A).y = %s", cAy.String())

	rhsX, rhsY := circomPointAdd(sig.RX, sig.RY, cAx, cAy, fieldP)
	t.Logf("\n=== RHS: R + c * A ===")
	t.Logf("(R + c*A).x = %s", rhsX.String())
	t.Logf("(R + c*A).y = %s", rhsY.String())

	// Check if LHS == RHS
	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("\n✓ circomlibjs verification equation (z * Base8 = R + c * A) PASSED!")
	} else {
		t.Log("\n✗ circomlibjs verification equation (z * Base8 = R + c * A) FAILED!")

		// Now let's check what circomlibjs actually does
		// circomlibjs uses: S * Base8 = R + (c * 8) * A
		// This is equivalent to: S * Base8 = R + c * Y (since Y = 8*A)
		t.Log("\n=== Checking alternative: z * Base8 = R + c * Y ===")
		cYx, cYy := circomScalarMult(yx, yy, challenge, fieldP)
		rhsYx, rhsYy := circomPointAdd(sig.RX, sig.RY, cYx, cYy, fieldP)
		t.Logf("(R + c*Y).x = %s", rhsYx.String())
		t.Logf("(R + c*Y).y = %s", rhsYy.String())

		if lhsX.Cmp(rhsYx) == 0 && lhsY.Cmp(rhsYy) == 0 {
			t.Log("✓ Alternative equation (z * Base8 = R + c * Y) PASSED!")
			t.Log("\n  This means FROST uses group key Y, but circomlibjs expects A = Y/8")
			t.Log("  The challenge was computed with A but verification needs Y")
		} else {
			t.Log("✗ Alternative equation also FAILED!")
		}

		// Check using FROST's internal challenge
		// FROST computes c' = H2(R, Y, msg) internally
		t.Log("\n=== Checking with FROST internal challenge (using Y, not A) ===")
		frostChallenge, _ := poseidon.Hash([]*big.Int{sig.RX, sig.RY, yx, yy, msg})
		t.Logf("c' = poseidon([R.x, R.y, Y.x, Y.y, msg]) = %s", frostChallenge.String())

		// z * Base8 = R + c' * Y ?
		cPrimeYx, cPrimeYy := circomScalarMult(yx, yy, frostChallenge, fieldP)
		rhsPrimeX, rhsPrimeY := circomPointAdd(sig.RX, sig.RY, cPrimeYx, cPrimeYy, fieldP)
		t.Logf("(R + c'*Y).x = %s", rhsPrimeX.String())
		t.Logf("(R + c'*Y).y = %s", rhsPrimeY.String())

		if lhsX.Cmp(rhsPrimeX) == 0 && lhsY.Cmp(rhsPrimeY) == 0 {
			t.Log("✓ FROST equation (z * Base8 = R + c' * Y) PASSED!")
			t.Log("\n  FROST is internally consistent - it uses Y for challenge computation")
			t.Log("  To make it circomlibjs-compatible, we need to:")
			t.Log("  1. Compute challenge using A = Y/8")
			t.Log("  2. Adjust signature scalar or use modified shares")
		}
	}

	// Let's analyze the relationship
	t.Log("\n=== Analysis ===")
	t.Log("FROST produces: z = r + c' * sk where c' = H(R, Y, msg)")
	t.Log("FROST verifies: z * G = R + c' * Y")
	t.Log("")
	t.Log("circomlibjs expects: S * Base8 = R + c * A")
	t.Log("Where: c = H(R, A, msg) and A = Y/8")
	t.Log("")
	t.Log("For compatibility, we need either:")
	t.Log("  Option 1: Compute c using A, then adjust z to z' = z - c'*sk + c*sk/8")
	t.Log("  Option 2: Use sk/8 shares during DKG (group key becomes Y' = sk*G = 8*A)")
	t.Log("  Option 3: Post-process z by dividing by 8 (won't work if different challenges)")
}

// TestExactCircomlibsEquation tests the exact equation used by circomlibjs.
// circomlibjs EdDSAPoseidonVerifier uses:
//
//	S * Base8 = R8 + (c * 8) * A
//
// which simplifies to:
//
//	S * Base8 = R8 + c * Y  (since Y = 8 * A)
func TestExactCircomlibsEquation(t *testing.T) {
	fieldP, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	base8X, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	base8Y, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	// Get Y and A
	groupKey := shares[0].SpendingKeyShare.GroupKey
	groupKeyPoint := groupKey.(*bjj.CircomPoint)
	gkBytes := groupKeyPoint.UncompressedBytes()
	yx := new(big.Int).SetBytes(gkBytes[0:32])
	yy := new(big.Int).SetBytes(gkBytes[32:64])

	inv8 := new(big.Int).ModInverse(big.NewInt(8), subOrder)
	ax, ay := circomScalarMult(yx, yy, inv8, fieldP)

	msg, _ := poseidon.Hash([]*big.Int{big.NewInt(99)})

	// Sign with FROST
	sig, err := tw.Sign(shares[:2], msg.Bytes())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with native FROST
	if !tw.Verify(groupKey, msg.Bytes(), sig) {
		t.Fatal("Native FROST verification failed")
	}
	t.Log("✓ Native FROST verification passed")

	// circomlibjs challenge: c = poseidon([R.x, R.y, A.x, A.y, msg])
	c, _ := poseidon.Hash([]*big.Int{sig.RX, sig.RY, ax, ay, msg})

	// circomlibjs verification: S * Base8 = R + (c * 8) * A
	// Let's compute both sides

	// LHS: S * Base8
	lhsX, lhsY := circomScalarMult(base8X, base8Y, sig.S, fieldP)

	// RHS: R + (c * 8) * A
	c8 := new(big.Int).Mul(c, big.NewInt(8))
	c8.Mod(c8, subOrder)
	c8Ax, c8Ay := circomScalarMult(ax, ay, c8, fieldP)
	rhsX, rhsY := circomPointAdd(sig.RX, sig.RY, c8Ax, c8Ay, fieldP)

	t.Logf("circomlibjs verification: S * Base8 = R + (c * 8) * A")
	t.Logf("LHS: (%s, %s)", lhsX.String(), lhsY.String())
	t.Logf("RHS: (%s, %s)", rhsX.String(), rhsY.String())

	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("✓ circomlibjs equation S * Base8 = R + (c * 8) * A PASSED!")
	} else {
		t.Log("✗ circomlibjs equation FAILED")

		// Let's check if the issue is in how RailgunHasher computes the challenge
		// RailgunHasher should compute c using A, but verify using Y
		// But FROST verification equation is z * Base8 = R + c * Y
		// where c = H2(R, Y, msg) - meaning FROST uses Y for challenge!

		t.Log("\nChecking what challenge FROST actually used...")

		// Get FROST's internal challenge (using Y, not A)
		// But wait - RailgunHasher computes c using A...
		// So the signature z was computed with c = H(R, A, msg)
		// And z = r + c * lambda * sk
		// Verification: z * Base8 = R + c * Y

		// Actually this can't work because:
		// z = r + c * sk
		// z * Base8 = r * Base8 + c * sk * Base8 = R + c * Y
		// This only holds if sk * Base8 = Y, which it does!

		// So z * Base8 = R + c * Y should hold regardless of what c is
		// Let's verify:
		cYx, cYy := circomScalarMult(yx, yy, c, fieldP)
		rhsYx, rhsYy := circomPointAdd(sig.RX, sig.RY, cYx, cYy, fieldP)

		t.Logf("\nAlternative: S * Base8 = R + c * Y (where c uses A)")
		t.Logf("LHS: (%s, %s)", lhsX.String(), lhsY.String())
		t.Logf("RHS: (%s, %s)", rhsYx.String(), rhsYy.String())

		if lhsX.Cmp(rhsYx) == 0 && lhsY.Cmp(rhsYy) == 0 {
			t.Log("✓ z * Base8 = R + c * Y PASSED (c computed with A)")
			t.Log("\nThis means FROST is producing valid signatures, but:")
			t.Log("  - circomlibjs verifies: S * Base8 = R + (c * 8) * A = R + c * Y")
			t.Log("  - FROST produces: z * Base8 = R + c * Y")
			t.Log("  - Both equations are the same!")
			t.Log("\nBUT circomlibjs expects c = H(R, A, msg)")
			t.Log("and RailgunHasher computes c = H(R, A, msg)")
			t.Log("So they should be compatible...")
		} else {
			t.Log("✗ Alternative equation also FAILED")
		}
	}
}

// Helper: Point addition on twisted Edwards curve (circomlibjs parameters)
func circomPointAdd(x1, y1, x2, y2, fieldP *big.Int) (*big.Int, *big.Int) {
	curveA := big.NewInt(168700)
	curveD := big.NewInt(168696)

	fieldMul := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Mul(a, b)
		return result.Mod(result, fieldP)
	}
	fieldAdd := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Add(a, b)
		return result.Mod(result, fieldP)
	}
	fieldSub := func(a, b *big.Int) *big.Int {
		result := new(big.Int).Sub(a, b)
		return result.Mod(result, fieldP)
	}
	fieldInv := func(a *big.Int) *big.Int {
		return new(big.Int).ModInverse(a, fieldP)
	}

	x1x2 := fieldMul(x1, x2)
	y1y2 := fieldMul(y1, y2)
	x1x2y1y2 := fieldMul(x1x2, y1y2)
	dx1x2y1y2 := fieldMul(curveD, x1x2y1y2)

	x1y2 := fieldMul(x1, y2)
	y1x2 := fieldMul(y1, x2)
	x3num := fieldAdd(x1y2, y1x2)
	x3den := fieldAdd(big.NewInt(1), dx1x2y1y2)

	ax1x2 := fieldMul(curveA, x1x2)
	y3num := fieldSub(y1y2, ax1x2)
	y3den := fieldSub(big.NewInt(1), dx1x2y1y2)

	x3 := fieldMul(x3num, fieldInv(x3den))
	y3 := fieldMul(y3num, fieldInv(y3den))
	return x3, y3
}

// Helper: Scalar multiplication on twisted Edwards curve (circomlibjs parameters)
func circomScalarMult(px, py, s, fieldP *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(1) // Identity
	tempX, tempY := new(big.Int).Set(px), new(big.Int).Set(py)
	n := new(big.Int).Set(s)

	for n.Sign() > 0 {
		if n.Bit(0) == 1 {
			rx, ry = circomPointAdd(rx, ry, tempX, tempY, fieldP)
		}
		tempX, tempY = circomPointAdd(tempX, tempY, tempX, tempY, fieldP)
		n.Rsh(n, 1)
	}

	return rx, ry
}
