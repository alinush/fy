package railgun

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestVector represents a test vector for cross-language verification.
type TestVector struct {
	// Private key (for single-key test)
	PrivateKey string `json:"privateKey"`

	// Public key coordinates
	PublicKeyX string `json:"publicKeyX"`
	PublicKeyY string `json:"publicKeyY"`

	// Message (as bigint string)
	Message string `json:"message"`

	// Signature
	SignatureRX string `json:"signatureRX"`
	SignatureRY string `json:"signatureRY"`
	SignatureS  string `json:"signatureS"`

	// FROST-specific
	IsFROST   bool `json:"isFrost"`
	Threshold int  `json:"threshold,omitempty"`
	Total     int  `json:"total,omitempty"`
}

// TestGenerateInteropVectors generates test vectors for TypeScript verification.
func TestGenerateInteropVectors(t *testing.T) {
	vectors := []TestVector{}

	// Test 1: Simple single-key signature (for baseline)
	t.Run("single-key", func(t *testing.T) {
		g := &bjj.BJJ{}

		// Generate random private key
		sk, err := g.RandomScalar(rand.Reader)
		if err != nil {
			t.Fatalf("RandomScalar() error = %v", err)
		}

		// Compute public key
		pk := g.NewPoint().ScalarMult(sk, g.Generator())
		bjjPK := pk.(*bjj.Point)
		pkBytes := bjjPK.UncompressedBytes()
		pkX := new(big.Int).SetBytes(pkBytes[0:32])
		pkY := new(big.Int).SetBytes(pkBytes[32:64])

		// Create message (like Railgun: poseidon hash of some inputs)
		msg, _ := poseidon.Hash([]*big.Int{big.NewInt(1), big.NewInt(2)})

		// For single key EdDSA, we can compute directly
		// But this won't match circomlibjs exactly due to nonce derivation
		// Let's just output the keys and message for now

		vectors = append(vectors, TestVector{
			PrivateKey: new(big.Int).SetBytes(sk.Bytes()).String(),
			PublicKeyX: pkX.String(),
			PublicKeyY: pkY.String(),
			Message:    msg.String(),
			IsFROST:    false,
		})
	})

	// Test 2: FROST threshold signature
	t.Run("frost-2of3", func(t *testing.T) {
		tw, err := NewThresholdWallet(2, 3)
		if err != nil {
			t.Fatalf("NewThresholdWallet() error = %v", err)
		}

		shares, err := tw.GenerateShares(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateShares() error = %v", err)
		}

		// Get circomlibjs-compatible public key A = Y/8
		gkX, gkY := shares[0].SpendingPublicKey()

		// Create message
		msg, _ := poseidon.Hash([]*big.Int{big.NewInt(42), big.NewInt(123)})

		// Sign with threshold
		sig, err := tw.Sign(shares[:2], msg.Bytes())
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		vectors = append(vectors, TestVector{
			PublicKeyX:  gkX.String(),
			PublicKeyY:  gkY.String(),
			Message:     msg.String(),
			SignatureRX: sig.RX.String(),
			SignatureRY: sig.RY.String(),
			SignatureS:  sig.S.String(),
			IsFROST:     true,
			Threshold:   2,
			Total:       3,
		})
	})

	// Test 3: FROST with known message format (like Railgun sighash)
	t.Run("frost-railgun-format", func(t *testing.T) {
		tw, err := NewThresholdWallet(2, 3)
		if err != nil {
			t.Fatalf("NewThresholdWallet() error = %v", err)
		}

		shares, err := tw.GenerateShares(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateShares() error = %v", err)
		}

		// Get circomlibjs-compatible public key A = Y/8
		gkX, gkY := shares[0].SpendingPublicKey()
		// Also get the internal group key for local verification
		groupKey := shares[0].SpendingKeyShare.GroupKey

		// Simulate Railgun sighash: poseidon(merkleRoot, boundParams, nullifier, commitment)
		merkleRoot := big.NewInt(12345)
		boundParams := big.NewInt(67890)
		nullifier := big.NewInt(11111)
		commitment := big.NewInt(22222)

		sighash, _ := poseidon.Hash([]*big.Int{merkleRoot, boundParams, nullifier, commitment})

		// Sign
		sig, err := tw.Sign(shares[:2], sighash.Bytes())
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		// Verify locally
		if !tw.Verify(groupKey, sighash.Bytes(), sig) {
			t.Error("Local verification failed")
		}

		vectors = append(vectors, TestVector{
			PublicKeyX:  gkX.String(),
			PublicKeyY:  gkY.String(),
			Message:     sighash.String(),
			SignatureRX: sig.RX.String(),
			SignatureRY: sig.RY.String(),
			SignatureS:  sig.S.String(),
			IsFROST:     true,
			Threshold:   2,
			Total:       3,
		})
	})

	// Output vectors as JSON (for debugging only, not written to file)
	output, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal error: %v", err)
	}

	t.Logf("Generated %d test vectors", len(vectors))
	t.Logf("Vectors:\n%s", string(output))
}

// TestGeneratorComparison compares Go and circomlibjs generators.
func TestGeneratorComparison(t *testing.T) {
	g := &bjj.BJJ{}
	gen := g.Generator().(*bjj.Point)
	genBytes := gen.UncompressedBytes()
	genX := new(big.Int).SetBytes(genBytes[0:32])
	genY := new(big.Int).SetBytes(genBytes[32:64])

	t.Logf("Go BJJ Generator X: %s", genX.String())
	t.Logf("Go BJJ Generator Y: %s", genY.String())

	// circomlibjs Generator
	circomlibGenX, _ := new(big.Int).SetString("995203441582195749578291179787384436505546430278305826713579947235728471134", 10)
	circomlibGenY, _ := new(big.Int).SetString("5472060717959818805561601436314318772137091100104008585924551046643952123905", 10)
	t.Logf("circomlibjs Generator X: %s", circomlibGenX.String())
	t.Logf("circomlibjs Generator Y: %s", circomlibGenY.String())

	// circomlibjs Base8 (= Generator * 8)
	circomlibBase8X, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	circomlibBase8Y, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)
	t.Logf("circomlibjs Base8 X: %s", circomlibBase8X.String())
	t.Logf("circomlibjs Base8 Y: %s", circomlibBase8Y.String())

	// Check if Go generator matches Base8
	if genX.Cmp(circomlibBase8X) == 0 && genY.Cmp(circomlibBase8Y) == 0 {
		t.Log("Go generator matches circomlibjs Base8!")
	} else if genX.Cmp(circomlibGenX) == 0 && genY.Cmp(circomlibGenY) == 0 {
		t.Log("Go generator matches circomlibjs Generator (not Base8)")
	} else {
		t.Log("Go generator doesn't match either circomlibjs point")
	}

	// Print BJJ order
	order := new(big.Int).SetBytes(g.Order())
	t.Logf("Go BJJ Order: %s", order.String())

	// circomlibjs subOrder
	circomlibSubOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	t.Logf("circomlibjs subOrder: %s", circomlibSubOrder.String())

	if order.Cmp(circomlibSubOrder) == 0 {
		t.Log("Go BJJ order matches circomlibjs subOrder!")
	}
}

// TestChallengeComputation tests that Poseidon hash produces consistent results.
// Note: This test verifies Poseidon compatibility, not the full FROST->circomlibjs flow.
// The full compatibility is tested via the TypeScript interop tests.
func TestChallengeComputation(t *testing.T) {
	// Test that Go and TypeScript Poseidon produce the same results
	rx, _ := new(big.Int).SetString("15660015125113847373452803938812646216659179634400049606474660404766542254104", 10)
	ry, _ := new(big.Int).SetString("8692981152208019440336609743985094216715238476060196656981549994926727866152", 10)
	pkx, _ := new(big.Int).SetString("21586427350797730007300450168853233945945069551530013585651522944120832329387", 10)
	pky, _ := new(big.Int).SetString("19614861110172003221189454544298559075237175528421464345119424450907898513368", 10)
	msg, _ := new(big.Int).SetString("13354932457729771147254927911602504548850183657014898888488396374653942452945", 10)

	// Compute challenge using poseidon
	challenge, err := poseidon.Hash([]*big.Int{rx, ry, pkx, pky, msg})
	if err != nil {
		t.Fatalf("poseidon.Hash() error = %v", err)
	}

	t.Logf("Go poseidon challenge: %s", challenge.String())

	// TypeScript computed: 4655811941120248895524330877515354220283882630255310626401054757163465263842
	expectedChallenge, _ := new(big.Int).SetString("4655811941120248895524330877515354220283882630255310626401054757163465263842", 10)

	if challenge.Cmp(expectedChallenge) != 0 {
		t.Errorf("Poseidon hash mismatch!\n  Go:         %s\n  TypeScript: %s", challenge.String(), expectedChallenge.String())
	} else {
		t.Log("Poseidon hash matches TypeScript!")
	}
}

// TestRailgunHasherCompatibility is now tested via the TypeScript interop tests.
// The hasher divides Y by 8 internally to compute A, which can only be properly
// tested with the full FROST signing flow and circomlibjs verification.
func TestRailgunHasherCompatibility(t *testing.T) {
	t.Log("RailgunHasher compatibility is tested via TypeScript interop tests")
	t.Log("See kohaku/packages/railgun/tests/frost-interop.test.ts")
}
