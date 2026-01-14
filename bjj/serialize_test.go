package bjj

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestCircomPointSerializeRoundTrip(t *testing.T) {
	g := NewCircomBJJ()

	// Generate a random scalar and compute a point
	s, _ := g.RandomScalar(rand.Reader)
	gen := g.Generator()
	p := g.NewPoint().ScalarMult(s, gen).(*CircomPoint)

	// Serialize
	bytes := p.UncompressedBytes()
	t.Logf("Serialized bytes length: %d", len(bytes))

	// Extract coordinates from serialized
	x1 := new(big.Int).SetBytes(bytes[:32])
	y1 := new(big.Int).SetBytes(bytes[32:64])
	t.Logf("Original X: %s", x1.String())
	t.Logf("Original Y: %s", y1.String())

	// Deserialize
	p2 := g.NewPoint().(*CircomPoint)
	if _, err := p2.SetUncompressedBytes(bytes); err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	// Get coordinates from deserialized
	bytes2 := p2.UncompressedBytes()
	x2 := new(big.Int).SetBytes(bytes2[:32])
	y2 := new(big.Int).SetBytes(bytes2[32:64])
	t.Logf("Loaded X: %s", x2.String())
	t.Logf("Loaded Y: %s", y2.String())

	// Compare
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Error("Serialization round-trip failed!")
	} else {
		t.Log("Serialization round-trip OK ✓")
	}

	// Also check .Bytes() which is used by RailgunHasher
	pBytes := p.Bytes()
	p2Bytes := p2.Bytes()
	t.Logf(".Bytes() length original: %d, loaded: %d", len(pBytes), len(p2Bytes))

	for i := range pBytes {
		if pBytes[i] != p2Bytes[i] {
			t.Errorf("Bytes() mismatch at index %d", i)
		}
	}
}
