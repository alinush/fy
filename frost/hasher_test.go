package frost

import (
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func TestPoseidonFieldReduction(t *testing.T) {
	// BN254 scalar field order
	bn254Order, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// BJJ base field is slightly larger than BN254 scalar field
	// This value is valid in BJJ base field but exceeds BN254 scalar field
	largeCoord, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208582", 10)

	t.Run("without reduction fails", func(t *testing.T) {
		rx := new(big.Int).Set(largeCoord)
		ry := big.NewInt(1234567890)
		ax := big.NewInt(9876543210)
		ay := big.NewInt(5555555555)
		msg, _ := new(big.Int).SetString("12345678901234567890", 10)

		_, err := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msg})
		if err == nil {
			t.Error("expected error for value outside field, got success")
		}
	})

	t.Run("with reduction succeeds", func(t *testing.T) {
		rx := new(big.Int).Set(largeCoord)
		ry := big.NewInt(1234567890)
		ax := big.NewInt(9876543210)
		ay := big.NewInt(5555555555)
		msg, _ := new(big.Int).SetString("12345678901234567890", 10)

		// Reduce all values
		rx.Mod(rx, bn254Order)
		ry.Mod(ry, bn254Order)
		ax.Mod(ax, bn254Order)
		ay.Mod(ay, bn254Order)
		msg.Mod(msg, bn254Order)

		hash, err := poseidon.Hash([]*big.Int{rx, ry, ax, ay, msg})
		if err != nil {
			t.Errorf("expected success after reduction, got error: %v", err)
		}
		if hash == nil || hash.Sign() == 0 {
			t.Error("expected non-zero hash")
		}
	})
}

func TestRailgunHasherH2FieldReduction(t *testing.T) {
	// Verify that H2 properly reduces all inputs before calling Poseidon
	// This is a sanity check that large coordinates don't cause panics

	h := NewRailgunHasher()
	g := bjj.NewCircomBJJ()

	// Create a point with coordinates that might exceed BN254 scalar field
	// Use identity point (0, 1) which is safe
	identityPoint := g.NewPoint()
	pointBytes := identityPoint.Bytes()

	// Use a large message that exceeds BN254 scalar field
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = 0xFF // All 1s = very large number
	}

	// This should not panic - H2 should reduce all values
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("H2 panicked with: %v", r)
		}
	}()

	_ = h.H2(g, pointBytes, pointBytes, msg)
}

func TestPoseidonSponge(t *testing.T) {
	t.Run("17 elements", func(t *testing.T) {
		elements := make([]*big.Int, 17)
		for i := range elements {
			elements[i] = big.NewInt(int64(i + 1))
		}
		hash, err := poseidonHash(elements)
		if err != nil {
			t.Fatalf("poseidonHash failed: %v", err)
		}
		if hash == nil || hash.Sign() == 0 {
			t.Error("expected non-zero hash")
		}
	})

	t.Run("32 elements", func(t *testing.T) {
		elements := make([]*big.Int, 32)
		for i := range elements {
			elements[i] = big.NewInt(int64(i * 7))
		}
		hash, err := poseidonHash(elements)
		if err != nil {
			t.Fatalf("poseidonHash failed: %v", err)
		}
		if hash == nil || hash.Sign() == 0 {
			t.Error("expected non-zero hash")
		}
	})

	t.Run("backward compatible with 16 or fewer", func(t *testing.T) {
		// Verify that <=16 elements produce the same result as direct poseidon.Hash
		elements := make([]*big.Int, 5)
		for i := range elements {
			elements[i] = big.NewInt(int64(i + 100))
		}
		directHash, err := poseidon.Hash(elements)
		if err != nil {
			t.Fatalf("poseidon.Hash failed: %v", err)
		}
		spongeHash, err := poseidonHash(elements)
		if err != nil {
			t.Fatalf("poseidonHash failed: %v", err)
		}
		if directHash.Cmp(spongeHash) != 0 {
			t.Errorf("sponge result differs from direct hash for <=16 elements")
		}
	})

	t.Run("exactly 16 elements", func(t *testing.T) {
		elements := make([]*big.Int, 16)
		for i := range elements {
			elements[i] = big.NewInt(int64(i + 1))
		}
		directHash, err := poseidon.Hash(elements)
		if err != nil {
			t.Fatalf("poseidon.Hash failed: %v", err)
		}
		spongeHash, err := poseidonHash(elements)
		if err != nil {
			t.Fatalf("poseidonHash failed: %v", err)
		}
		if directHash.Cmp(spongeHash) != 0 {
			t.Errorf("sponge result differs from direct hash at boundary (16 elements)")
		}
	})

	t.Run("empty returns error", func(t *testing.T) {
		_, err := poseidonHash(nil)
		if err == nil {
			t.Error("expected error for empty input")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		elements := make([]*big.Int, 20)
		for i := range elements {
			elements[i] = big.NewInt(int64(i + 42))
		}
		h1, _ := poseidonHash(elements)
		h2, _ := poseidonHash(elements)
		if h1.Cmp(h2) != 0 {
			t.Error("same input produced different outputs")
		}
	})
}

func TestPoseidonHasher_5Signers(t *testing.T) {
	// Verify that PoseidonHasher works with 5 signers (was previously limited to 3)
	g := bjj.NewCircomBJJ()
	h := NewPoseidonHasher()

	// Simulate 5 signers: encCommitList for 5 signers = 4 + 5*108 = 544 bytes
	encCommitList := make([]byte, 544)
	for i := range encCommitList {
		encCommitList[i] = byte(i % 256)
	}
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i)
	}
	signerID := make([]byte, 32)
	signerID[31] = 1

	// H1 should not panic
	result := h.H1(g, msg, encCommitList, signerID)
	if result == nil || result.IsZero() {
		t.Error("H1 returned nil or zero for 5 signers")
	}

	// H5 should not panic
	h5Result := h.H5(g, encCommitList)
	if len(h5Result) != 32 {
		t.Errorf("H5 returned %d bytes, expected 32", len(h5Result))
	}
}
