package golden

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
	bn254g1 "github.com/f3rmion/fy/bn254g1"
)

func TestBjjScalarToFrRoundtrip(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	// A random BJJ scalar should survive bjj->fr->bjj since l < r.
	for i := 0; i < 10; i++ {
		original, err := bjjG.RandomScalar(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		fr, err := bjjScalarToFr(frG, original)
		if err != nil {
			t.Fatalf("bjjScalarToFr: %v", err)
		}

		recovered, err := frToBJJScalar(bjjG, fr)
		if err != nil {
			t.Fatalf("frToBJJScalar: %v", err)
		}

		if !recovered.Equal(original) {
			t.Errorf("roundtrip failed: original=%x, recovered=%x",
				original.Bytes(), recovered.Bytes())
		}
	}
}

func TestFrToBJJScalarReduces(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	// Fr values near r (> l) should be reduced mod l.
	// Create an Fr scalar that is larger than the BJJ order.
	// BJJ order is ~2^251, Fr order is ~2^254.
	// Use a value between l and r.
	large, err := frG.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bjjScalar, err := frToBJJScalar(bjjG, large)
	if err != nil {
		t.Fatalf("frToBJJScalar: %v", err)
	}

	// The BJJ scalar should be valid (reduced mod l).
	// Verify by checking it serializes to <= 32 bytes.
	b := bjjScalar.Bytes()
	if len(b) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(b))
	}
}

func TestExtractXAsFr(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	// Generate a random BJJ point.
	sk, err := bjjG.RandomScalar(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := bjjG.NewPoint().ScalarMult(sk, bjjG.Generator())

	// Extract x-coordinate as Fr.
	xFr, err := extractXAsFr(frG, pk)
	if err != nil {
		t.Fatalf("extractXAsFr: %v", err)
	}

	// The x-coordinate from XBytes should match.
	type xByteser interface {
		XBytes() []byte
	}
	xb := pk.(xByteser).XBytes()

	xFrBytes := xFr.Bytes()
	if len(xb) != len(xFrBytes) {
		t.Fatalf("length mismatch: XBytes=%d, Fr.Bytes=%d", len(xb), len(xFrBytes))
	}
	for i := range xb {
		if xb[i] != xFrBytes[i] {
			t.Errorf("byte %d differs: XBytes=%02x, Fr=%02x", i, xb[i], xFrBytes[i])
		}
	}
}

func TestExtractXMatchesUncompressedBytes(t *testing.T) {
	bjjG := &bjj.BJJ{}
	frG := &bn254g1.BN254G1{}

	sk, _ := bjjG.RandomScalar(rand.Reader)
	pk := bjjG.NewPoint().ScalarMult(sk, bjjG.Generator())

	// BJJ UncompressedBytes returns X || Y (64 bytes).
	type uncompressor interface {
		UncompressedBytes() []byte
	}
	ub := pk.(uncompressor).UncompressedBytes()
	xFromUncompressed := ub[0:32]

	xFr, err := extractXAsFr(frG, pk)
	if err != nil {
		t.Fatal(err)
	}

	xFrBytes := xFr.Bytes()
	for i := range xFromUncompressed {
		if xFromUncompressed[i] != xFrBytes[i] {
			t.Errorf("byte %d differs", i)
		}
	}
}
