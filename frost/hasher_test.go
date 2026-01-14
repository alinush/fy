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
