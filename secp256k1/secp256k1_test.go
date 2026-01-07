package secp256k1

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/group"
)

func TestScalar(t *testing.T) {
	g := New()

	t.Run("AddSub", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)
		b, _ := g.RandomScalar(rand.Reader)

		sum := g.NewScalar().Add(a, b)
		diff := g.NewScalar().Sub(sum, b)

		if !diff.Equal(a) {
			t.Error("(a+b)-b != a")
		}
	})

	t.Run("MulInvert", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)
		aInv, err := g.NewScalar().Invert(a)
		if err != nil {
			t.Fatal(err)
		}

		product := g.NewScalar().Mul(a, aInv)

		// a * a^-1 = 1 => product
		// check if product equals one
		// if product = 1, then product * b = b for any b
		b, _ := g.RandomScalar(rand.Reader)
		result := g.NewScalar().Mul(product, b)

		if !result.Equal(b) {
			t.Error("a*a^-1 != 1")
		}
	})

	t.Run("InvertZeroFails", func(t *testing.T) {
		zero := g.NewScalar()
		_, err := g.NewScalar().Invert(zero)
		if err == nil {
			t.Error("expected error inverting zero")
		}
	})

	t.Run("Negate", func(t *testing.T) {
		zero := g.NewScalar()
		a, _ := g.RandomScalar(rand.Reader)
		negA := g.NewScalar().Negate(a)

		result := g.NewScalar().Add(a, negA)

		if !result.Equal(zero) {
			t.Error("negating scalar failed")
		}
	})

	t.Run("BytesRoundtrip", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)

		bytes := a.Bytes()
		restored, err := g.NewScalar().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(a) {
			t.Error("scalar bytes roundtrip failed")
		}
	})

	t.Run("NewScalarIsZero", func(t *testing.T) {
		zero := g.NewScalar()
		if !zero.IsZero() {
			t.Error("new scalar should be zero")
		}
	})

	t.Run("Equal", func(t *testing.T) {
		var a group.Scalar
		for {
			// edge case is a==0 where -a==a
			// for assertion below, so we exclude a==0
			a, _ = g.RandomScalar(rand.Reader)
			if !a.IsZero() {
				break
			}
		}
		b := g.NewScalar().Set(a)
		if !a.Equal(b) {
			t.Error("copied scalar should equal original")
		}

		b = g.NewScalar().Negate(a)
		if a.Equal(b) {
			t.Error("a should not equal -a")
		}
	})
}

func TestPoint(t *testing.T) {
	g := New()

	t.Run("AddSub", func(t *testing.T) {
		s1, _ := g.RandomScalar(rand.Reader)
		s2, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s1, g.Generator())
		Q := g.NewPoint().ScalarMult(s2, g.Generator())

		sum := g.NewPoint().Add(P, Q)
		diff := g.NewPoint().Sub(sum, Q)

		if !diff.Equal(P) {
			t.Error("(P+Q)-Q != P")
		}
	})

	t.Run("Negate", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())
		negP := g.NewPoint().Negate(P)

		result := g.NewPoint().Add(P, negP)

		if !result.IsIdentity() {
			t.Error("P + (-P) != identity")
		}
	})

	t.Run("CompressedBytesRoundtrip", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())

		bytes := P.Bytes()
		if len(bytes) != 33 {
			t.Errorf("compressed bytes should be 33, got %d", len(bytes))
		}

		restored, err := g.NewPoint().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(P) {
			t.Error("point compressed bytes roundtrip failed")
		}
	})

	t.Run("UncompressedBytesRoundtrip", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator()).(*Point)

		uncompressed := P.UncompressedBytes()
		if len(uncompressed) != 65 {
			t.Errorf("uncompressed bytes should be 65, got %d", len(uncompressed))
		}
		if uncompressed[0] != 0x04 {
			t.Errorf("uncompressed prefix should be 0x04, got 0x%02x", uncompressed[0])
		}

		restored, err := g.NewPoint().SetBytes(uncompressed)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(P) {
			t.Error("uncompressed bytes roundtrip failed")
		}
	})

	t.Run("IsIdentity", func(t *testing.T) {
		identity := g.NewPoint()
		if !identity.IsIdentity() {
			t.Error("new point should be identity")
		}

		gen := g.Generator()
		if gen.IsIdentity() {
			t.Error("generator should not be identity")
		}
	})

	t.Run("ScalarMultDistributive", func(t *testing.T) {
		// Test: (a+b)*G == a*G + b*G
		a, _ := g.RandomScalar(rand.Reader)
		b, _ := g.RandomScalar(rand.Reader)

		// LHS: (a+b)*G
		aPlusB := g.NewScalar().Add(a, b)
		lhs := g.NewPoint().ScalarMult(aPlusB, g.Generator())

		// RHS: a*G + b*G
		aG := g.NewPoint().ScalarMult(a, g.Generator())
		bG := g.NewPoint().ScalarMult(b, g.Generator())
		rhs := g.NewPoint().Add(aG, bG)

		if !lhs.Equal(rhs) {
			t.Errorf("(a+b)*G != a*G + b*G")
			t.Logf("a: %x", a.Bytes())
			t.Logf("b: %x", b.Bytes())
			t.Logf("LHS: %x", lhs.Bytes())
			t.Logf("RHS: %x", rhs.Bytes())
		}
	})

	t.Run("ScalarMultAssociative", func(t *testing.T) {
		// Test: k*(b*G) == (k*b)*G
		b, _ := g.RandomScalar(rand.Reader)

		// k = 2
		k := g.NewScalar()
		buf := make([]byte, 32)
		buf[31] = 2
		k.SetBytes(buf)

		// LHS: (k*b)*G
		kb := g.NewScalar().Mul(k, b)
		lhs := g.NewPoint().ScalarMult(kb, g.Generator())

		// RHS: k*(b*G)
		bG := g.NewPoint().ScalarMult(b, g.Generator())
		rhs := g.NewPoint().ScalarMult(k, bG)

		if !lhs.Equal(rhs) {
			t.Errorf("k*(b*G) != (k*b)*G")
			t.Logf("k: %x", k.Bytes())
			t.Logf("b: %x", b.Bytes())
			t.Logf("kb: %x", kb.Bytes())
			t.Logf("LHS (kb*G): %x", lhs.Bytes())
			t.Logf("RHS (k*bG): %x", rhs.Bytes())
		}
	})

	t.Run("ScalarMultDistributiveWithCoefficient", func(t *testing.T) {
		// Test: (a + k*b)*G == a*G + k*(b*G)
		// This is the exact pattern used in DKG verification
		a, _ := g.RandomScalar(rand.Reader)
		b, _ := g.RandomScalar(rand.Reader)

		// k = 2 (like recipient ID 2)
		k := g.NewScalar()
		buf := make([]byte, 32)
		buf[31] = 2
		k.SetBytes(buf)

		// LHS: (a + k*b)*G
		kb := g.NewScalar().Mul(k, b)
		aPlusKB := g.NewScalar().Add(a, kb)
		lhs := g.NewPoint().ScalarMult(aPlusKB, g.Generator())

		// RHS: a*G + k*(b*G)
		aG := g.NewPoint().ScalarMult(a, g.Generator())
		bG := g.NewPoint().ScalarMult(b, g.Generator())
		kbG := g.NewPoint().ScalarMult(k, bG)
		rhs := g.NewPoint().Add(aG, kbG)

		if !lhs.Equal(rhs) {
			t.Errorf("(a + k*b)*G != a*G + k*(b*G)")
			t.Logf("a: %x", a.Bytes())
			t.Logf("b: %x", b.Bytes())
			t.Logf("k: %x", k.Bytes())
			t.Logf("LHS: %x", lhs.Bytes())
			t.Logf("RHS: %x", rhs.Bytes())
		}
	})

	t.Run("IdentityBytesRoundtrip", func(t *testing.T) {
		identity := g.NewPoint()
		bytes := identity.Bytes()

		restored, err := g.NewPoint().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.IsIdentity() {
			t.Error("identity bytes roundtrip failed")
		}
	})

	t.Run("GeneratorBytesRoundtrip", func(t *testing.T) {
		gen := g.Generator()
		bytes := gen.Bytes()

		restored, err := g.NewPoint().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(gen) {
			t.Error("generator bytes roundtrip failed")
		}
	})
}

func TestGroup(t *testing.T) {
	g := New()

	t.Run("OrderIsCorrect", func(t *testing.T) {
		order := g.Order()
		if len(order) != 32 {
			t.Errorf("order should be 32 bytes, got %d", len(order))
		}

		// secp256k1 order starts with 0xFF...
		if order[0] != 0xFF {
			t.Errorf("order should start with 0xFF, got 0x%02x", order[0])
		}
	})

	t.Run("HashToScalar", func(t *testing.T) {
		s1, _ := g.HashToScalar([]byte("test message"))
		s2, _ := g.HashToScalar([]byte("test message"))
		s3, _ := g.HashToScalar([]byte("different message"))

		if !s1.Equal(s2) {
			t.Error("same input should produce same hash")
		}

		if s1.Equal(s3) {
			t.Error("different input should produce different hash")
		}
	})
}
