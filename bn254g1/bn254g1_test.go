package bn254g1

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/group"
)

func TestScalarArithmetic(t *testing.T) {
	g := &BN254G1{}

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
}

func TestScalarSerialization(t *testing.T) {
	g := &BN254G1{}

	t.Run("BytesRoundtrip", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)

		bytes := a.Bytes()
		if len(bytes) != 32 {
			t.Errorf("scalar bytes should be 32, got %d", len(bytes))
		}

		restored, err := g.NewScalar().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(a) {
			t.Error("scalar bytes roundtrip failed")
		}
	})

	t.Run("ZeroScalar", func(t *testing.T) {
		zero := g.NewScalar()
		if !zero.IsZero() {
			t.Error("new scalar should be zero")
		}

		bytes := zero.Bytes()
		allZero := true
		for _, b := range bytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			t.Error("zero scalar bytes should be all zero")
		}
	})

	t.Run("Zero", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)
		if a.IsZero() {
			t.Fatal("random scalar should not be zero")
		}

		// Grab the internal bytes before zeroing
		preBytes := a.Bytes()
		allZero := true
		for _, b := range preBytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("random scalar bytes should not be all zero")
		}

		a.Zero()
		if !a.IsZero() {
			t.Error("scalar should be zero after Zero()")
		}
	})

	t.Run("Equal", func(t *testing.T) {
		var a group.Scalar
		for {
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

func TestPointArithmetic(t *testing.T) {
	g := &BN254G1{}

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

	t.Run("ScalarMult", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())
		if P.IsIdentity() {
			t.Error("s*G should not be identity for random s")
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
}

func TestPointSerialization(t *testing.T) {
	g := &BN254G1{}

	t.Run("BytesRoundtrip", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())

		bytes := P.Bytes()
		restored, err := g.NewPoint().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(P) {
			t.Error("point bytes roundtrip failed")
		}
	})

	t.Run("Identity", func(t *testing.T) {
		identity := g.NewPoint()
		if !identity.IsIdentity() {
			t.Error("new point should be identity")
		}

		gen := g.Generator()
		if gen.IsIdentity() {
			t.Error("generator should not be identity")
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

func TestGeneratorOnCurve(t *testing.T) {
	g := &BN254G1{}
	gen := g.Generator().(*Point)

	if gen.IsIdentity() {
		t.Fatal("generator should not be identity")
	}

	// Verify it's on the curve by checking a roundtrip through serialization
	bytes := gen.Bytes()
	restored, err := g.NewPoint().SetBytes(bytes)
	if err != nil {
		t.Fatalf("generator failed serialization roundtrip (not on curve?): %v", err)
	}
	if !restored.Equal(gen) {
		t.Error("generator roundtrip produced different point")
	}
}

func TestRandomScalar(t *testing.T) {
	g := &BN254G1{}

	t.Run("NonZero", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			s, err := g.RandomScalar(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if s.IsZero() {
				t.Fatal("random scalar should not be zero")
			}
		}
	})

	t.Run("Distinct", func(t *testing.T) {
		s1, _ := g.RandomScalar(rand.Reader)
		s2, _ := g.RandomScalar(rand.Reader)
		if s1.Equal(s2) {
			t.Error("two random scalars should be distinct (extremely unlikely collision)")
		}
	})
}

func TestHashToScalar(t *testing.T) {
	g := &BN254G1{}

	t.Run("Deterministic", func(t *testing.T) {
		s1, _ := g.HashToScalar([]byte("test message"))
		s2, _ := g.HashToScalar([]byte("test message"))

		if !s1.Equal(s2) {
			t.Error("same input should produce same hash")
		}
	})

	t.Run("DifferentInputsDiffer", func(t *testing.T) {
		s1, _ := g.HashToScalar([]byte("test message"))
		s2, _ := g.HashToScalar([]byte("different message"))

		if s1.Equal(s2) {
			t.Error("different input should produce different hash")
		}
	})

	t.Run("NonZero", func(t *testing.T) {
		s, _ := g.HashToScalar([]byte("test"))
		if s.IsZero() {
			t.Error("hash to scalar should not produce zero")
		}
	})
}

func TestIdentityBehavior(t *testing.T) {
	g := &BN254G1{}

	t.Run("AddIdentity", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())
		identity := g.NewPoint()

		result := g.NewPoint().Add(P, identity)
		if !result.Equal(P) {
			t.Error("P + Identity != P")
		}

		result = g.NewPoint().Add(identity, P)
		if !result.Equal(P) {
			t.Error("Identity + P != P")
		}
	})

	t.Run("SubSelf", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())

		result := g.NewPoint().Sub(P, P)
		if !result.IsIdentity() {
			t.Error("P - P != Identity")
		}
	})
}

func TestScalarMultGenerator(t *testing.T) {
	g := &BN254G1{}

	// 1*G should equal G
	one := g.NewScalar()
	buf := make([]byte, 32)
	buf[31] = 1
	one.SetBytes(buf)

	oneG := g.NewPoint().ScalarMult(one, g.Generator())
	if !oneG.Equal(g.Generator()) {
		t.Error("1*G != G")
	}

	// Verify via bytes roundtrip
	bytes := oneG.Bytes()
	restored, err := g.NewPoint().SetBytes(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Equal(g.Generator()) {
		t.Error("restored 1*G != G")
	}

	// 0*G should be identity
	zero := g.NewScalar()
	zeroG := g.NewPoint().ScalarMult(zero, g.Generator())
	if !zeroG.IsIdentity() {
		t.Error("0*G != Identity")
	}
}

func TestOrderIsCorrect(t *testing.T) {
	g := &BN254G1{}
	order := g.Order()
	if len(order) != 32 {
		t.Errorf("order should be 32 bytes, got %d", len(order))
	}

	// BN254 scalar field order starts with 0x30
	if order[0] != 0x30 {
		t.Errorf("order should start with 0x30, got 0x%02x", order[0])
	}
}
