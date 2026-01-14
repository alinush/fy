package bjj

import (
	"math/big"
	"testing"
)

func TestCircomBJJGenerator(t *testing.T) {
	g := NewCircomBJJ()
	gen := g.Generator().(*CircomPoint)
	unc := gen.UncompressedBytes()
	x := new(big.Int).SetBytes(unc[:32])
	y := new(big.Int).SetBytes(unc[32:])

	base8x, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	base8y, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	t.Logf("CircomBJJ Generator:")
	t.Logf("  X: %s", x.String())
	t.Logf("  Y: %s", y.String())
	t.Logf("\nExpected Base8:")
	t.Logf("  X: %s", base8x.String())
	t.Logf("  Y: %s", base8y.String())

	if x.Cmp(base8x) != 0 || y.Cmp(base8y) != 0 {
		t.Error("Generator does not match Base8!")
	} else {
		t.Log("Generator matches Base8 ✓")
	}
}
