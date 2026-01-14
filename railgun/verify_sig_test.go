package railgun

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestVerifyActualSignature verifies the actual signature from the failing unshield
func TestVerifyActualSignature(t *testing.T) {
	// Field modulus (BN254)
	fieldP, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	subOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	// Base8 generator
	base8X, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	base8Y, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	// Actual values from the latest failing unshield
	ax, _ := new(big.Int).SetString("20026889608777403795665626800907346608158208569402487973918721176355059291675", 10)
	ay, _ := new(big.Int).SetString("13200796977118599908275481645910090925733298062348995995426837734696675042566", 10)

	rx, _ := new(big.Int).SetString("19305565585201351841753416215756429401666555254609991991707505851312759774864", 10)
	ry, _ := new(big.Int).SetString("21282012280664667577405162615843447752666302418672774231131397311175112635230", 10)
	s, _ := new(big.Int).SetString("1297527204203028169718415960767588314192185288215579339133960283402655473001", 10)

	merkleRoot, _ := new(big.Int).SetString("17552377079336855460559782674766413486911246095652786188302090158520831953820", 10)
	boundParamsHash, _ := new(big.Int).SetString("10508282044751358312047147137927485277634689874167476832403767496224875566181", 10)
	nullifier, _ := new(big.Int).SetString("6023712089153214933912614285799140423397393962116999821496686840427132622085", 10)
	commitment1, _ := new(big.Int).SetString("16349600140358136214326909296046405597997078358167262783336343471420937803415", 10)
	commitment2, _ := new(big.Int).SetString("8637041560005557198654842436011153738145765657984692693943686634307380851189", 10)

	t.Log("=== Verifying Actual Signature ===")
	t.Logf("Public Key A: (%s, %s)", ax.String(), ay.String())
	t.Logf("Signature R: (%s, %s)", rx.String(), ry.String())
	t.Logf("Signature S: %s", s.String())

	// Compute the message hash as the signer would have
	// msg = poseidon(merkleRoot, boundParamsHash, nullifiers..., commitments...)
	msgHash, err := poseidon.Hash([]*big.Int{merkleRoot, boundParamsHash, nullifier, commitment1, commitment2})
	if err != nil {
		t.Fatalf("poseidon.Hash() error = %v", err)
	}
	t.Logf("Computed message hash: %s", msgHash.String())
	t.Logf("Expected message hash: 5490089411662003245665387211891846584887876999214360353985710394781499540523")

	// Compute challenge c = poseidon([R.x, R.y, A.x, A.y, msg])
	// This is how circomlibjs computes the challenge
	challenge, err := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msgHash})
	if err != nil {
		t.Fatalf("poseidon.Hash() error = %v", err)
	}
	t.Logf("Challenge c: %s", challenge.String())

	// Verify: S * Base8 = R + (c * 8) * A
	// LHS: S * Base8
	lhsX, lhsY := circomScalarMult(base8X, base8Y, s, fieldP)
	t.Logf("LHS (S * Base8): (%s, %s)", lhsX.String(), lhsY.String())

	// RHS: R + (c * 8) * A
	c8 := new(big.Int).Mul(challenge, big.NewInt(8))
	c8.Mod(c8, subOrder)
	c8Ax, c8Ay := circomScalarMult(ax, ay, c8, fieldP)
	rhsX, rhsY := circomPointAdd(rx, ry, c8Ax, c8Ay, fieldP)
	t.Logf("RHS (R + c*8*A): (%s, %s)", rhsX.String(), rhsY.String())

	if lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0 {
		t.Log("✓ circomlibjs equation S * Base8 = R + (c * 8) * A PASSED!")
	} else {
		t.Error("✗ circomlibjs equation FAILED!")

		// Try Y = 8*A and verify: S * Base8 = R + c * Y
		yx, yy := circomScalarMult(ax, ay, big.NewInt(8), fieldP)
		t.Logf("Group key Y = 8*A: (%s, %s)", yx.String(), yy.String())

		cYx, cYy := circomScalarMult(yx, yy, challenge, fieldP)
		rhsYx, rhsYy := circomPointAdd(rx, ry, cYx, cYy, fieldP)
		t.Logf("Alternative RHS (R + c * Y): (%s, %s)", rhsYx.String(), rhsYy.String())

		if lhsX.Cmp(rhsYx) == 0 && lhsY.Cmp(rhsYy) == 0 {
			t.Log("✓ Alternative equation (S * Base8 = R + c * Y) PASSED")
			t.Log("This suggests FROST is using Y for challenge instead of A")
		}
	}

	// Also check if FROST used Y instead of A for challenge computation
	// Y = 8 * A
	yx, yy := circomScalarMult(ax, ay, big.NewInt(8), fieldP)
	frostChallenge, _ := poseidon.Hash([]*big.Int{rx, ry, yx, yy, msgHash})
	t.Logf("\nFROST challenge (using Y instead of A): %s", frostChallenge.String())

	// Check: S * Base8 = R + frostChallenge * Y
	fcYx, fcYy := circomScalarMult(yx, yy, frostChallenge, fieldP)
	rhsFrostX, rhsFrostY := circomPointAdd(rx, ry, fcYx, fcYy, fieldP)
	t.Logf("FROST verification RHS (R + c' * Y): (%s, %s)", rhsFrostX.String(), rhsFrostY.String())

	if lhsX.Cmp(rhsFrostX) == 0 && lhsY.Cmp(rhsFrostY) == 0 {
		t.Log("✓ FROST equation (using Y for challenge) PASSED!")
		t.Log("\n*** ROOT CAUSE: RailgunHasher is using Y for challenge, but circomlibjs expects A ***")
		t.Log("The hasher should compute c = poseidon([R.x, R.y, A.x, A.y, msg]) where A = Y/8")
	}
}
