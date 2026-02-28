package golden

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func TestAztecFieldEncoding(t *testing.T) {
	// Known value: the 32-byte Aztec encoding [w0][w1][w2][w3] where each
	// word is big-endian and w0 is least significant.
	// Standard big-endian should be [w3][w2][w1][w0].
	src := []byte{
		// w0 (least significant)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// w1
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		// w2
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		// w3 (most significant)
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	}

	var dst [32]byte
	aztecToStdBE(dst[:], src)

	want := []byte{
		// w3 (most significant first in big-endian)
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		// w2
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		// w1
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		// w0 (least significant last)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}

	for i := range dst {
		if dst[i] != want[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, dst[i], want[i])
		}
	}
}

func TestAztecFieldEncodingIdentity(t *testing.T) {
	// Double-applying aztecToStdBE should return the original.
	src := make([]byte, 32)
	for i := range src {
		src[i] = byte(i)
	}

	var mid, roundtrip [32]byte
	aztecToStdBE(mid[:], src)
	aztecToStdBE(roundtrip[:], mid[:])

	for i := range src {
		if roundtrip[i] != src[i] {
			t.Fatalf("roundtrip byte %d: got 0x%02x, want 0x%02x", i, roundtrip[i], src[i])
		}
	}
}

func TestBuildCanonicalSRS(t *testing.T) {
	// Use unsafekzg to generate a reference SRS, then verify our builder
	// produces a pairing-consistent SRS from the same G1/G2 data.
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		scs.NewBuilder,
		&EVRFCircuit{},
	)
	if err != nil {
		t.Fatalf("compiling circuit: %v", err)
	}

	refCanonical, _, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generating reference SRS: %v", err)
	}

	refSRS := refCanonical.(*kzg_bn254.SRS)
	sizeCanonical, _ := plonk.SRSSize(ccs)

	// Extract G1 powers (τ^1 through τ^(n-1)) and τ·G2.
	g1Powers := make([]bn254.G1Affine, sizeCanonical-1)
	copy(g1Powers, refSRS.Pk.G1[1:sizeCanonical])
	tauG2 := refSRS.Vk.G2[1]

	// Build our SRS.
	built, err := buildCanonicalSRS(g1Powers, tauG2, sizeCanonical)
	if err != nil {
		t.Fatalf("buildCanonicalSRS: %v", err)
	}

	// Verify batch pairing consistency.
	if err := verifySRSConsistency(built); err != nil {
		t.Fatalf("pairing consistency: %v", err)
	}

	// Verify G1 generator is at index 0.
	_, _, g1Gen, _ := bn254.Generators()
	if !built.Pk.G1[0].Equal(&g1Gen) {
		t.Error("Pk.G1[0] is not the G1 generator")
	}

	// Verify sizes.
	if len(built.Pk.G1) != sizeCanonical {
		t.Errorf("Pk.G1 length: got %d, want %d", len(built.Pk.G1), sizeCanonical)
	}
}

func TestSRSCacheRoundTrip(t *testing.T) {
	// Build a small SRS, cache it, reload it, and verify sizes match.
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		scs.NewBuilder,
		&EVRFCircuit{},
	)
	if err != nil {
		t.Fatalf("compiling circuit: %v", err)
	}

	refCanonical, refLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generating reference SRS: %v", err)
	}

	canonicalSRS := refCanonical.(*kzg_bn254.SRS)
	lagrangeSRS := refLagrange.(*kzg_bn254.SRS)

	// Write to temp directory.
	tmpDir := t.TempDir()
	if err := cacheSRS(tmpDir, canonicalSRS, lagrangeSRS); err != nil {
		t.Fatalf("cacheSRS: %v", err)
	}

	// Verify files exist and have restricted permissions.
	for _, name := range []string{srsCanonicalFile, srsLagrangeFile} {
		info, err := os.Stat(filepath.Join(tmpDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
		perm := info.Mode().Perm()
		if perm&0o077 != 0 {
			t.Errorf("%s has too-permissive mode: %o", name, perm)
		}
	}

	// Reload and validate sizes.
	sizeCanonical, sizeLagrange := plonk.SRSSize(ccs)
	loadedCanon, loadedLag, err := loadCachedSRS(tmpDir, sizeCanonical, sizeLagrange)
	if err != nil {
		t.Fatalf("loadCachedSRS: %v", err)
	}

	if len(loadedCanon.Pk.G1) < sizeCanonical {
		t.Errorf("reloaded canonical too small: %d < %d", len(loadedCanon.Pk.G1), sizeCanonical)
	}
	if len(loadedLag.Pk.G1) < sizeLagrange {
		t.Errorf("reloaded lagrange too small: %d < %d", len(loadedLag.Pk.G1), sizeLagrange)
	}

	// Verify reloaded SRS passes batch pairing check.
	if err := verifySRSConsistency(loadedCanon); err != nil {
		t.Fatalf("reloaded SRS consistency check failed: %v", err)
	}
}

func TestVerifySRSConsistency_BadG2(t *testing.T) {
	// Build a valid SRS, corrupt τ·G2, and verify the batch check fails.
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		scs.NewBuilder,
		&EVRFCircuit{},
	)
	if err != nil {
		t.Fatalf("compiling circuit: %v", err)
	}

	refCanonical, _, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generating reference SRS: %v", err)
	}

	srs := refCanonical.(*kzg_bn254.SRS)

	// Corrupt τ·G2 by setting it to the G2 generator (wrong τ).
	_, _, _, g2Gen := bn254.Generators()
	srs.Vk.G2[1].Set(&g2Gen)

	if err := verifySRSConsistency(srs); err == nil {
		t.Error("expected batch pairing check to fail with corrupted G2")
	}
}

func TestVerifySRSConsistency_CorruptedG1Power(t *testing.T) {
	// Build a valid SRS, corrupt a middle G1 power, verify the batch check catches it.
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		scs.NewBuilder,
		&EVRFCircuit{},
	)
	if err != nil {
		t.Fatalf("compiling circuit: %v", err)
	}

	refCanonical, _, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generating reference SRS: %v", err)
	}

	srs := refCanonical.(*kzg_bn254.SRS)

	// Corrupt a middle G1 power by setting it to the generator.
	_, _, g1Gen, _ := bn254.Generators()
	midIdx := len(srs.Pk.G1) / 2
	srs.Pk.G1[midIdx].Set(&g1Gen)

	if err := verifySRSConsistency(srs); err == nil {
		t.Errorf("expected batch pairing check to fail with corrupted G1 power at index %d", midIdx)
	}
}

func TestParseIgnitionTranscript_Synthetic(t *testing.T) {
	// Construct a synthetic Aztec transcript with known G1/G2 points
	// and verify parseIgnitionTranscript parses them correctly.
	_, _, g1Gen, g2Gen := bn254.Generators()

	numG1 := 3
	numG2 := 2

	// Build manifest (28 bytes, all big-endian).
	var manifest [28]byte
	binary.BigEndian.PutUint32(manifest[0:4], 0)       // TranscriptNumber
	binary.BigEndian.PutUint32(manifest[4:8], 1)       // TotalTranscripts
	binary.BigEndian.PutUint32(manifest[8:12], 3)      // TotalG1Points
	binary.BigEndian.PutUint32(manifest[12:16], 2)     // TotalG2Points
	binary.BigEndian.PutUint32(manifest[16:20], uint32(numG1)) // NumG1Points
	binary.BigEndian.PutUint32(manifest[20:24], uint32(numG2)) // NumG2Points
	binary.BigEndian.PutUint32(manifest[24:28], 0)     // StartFrom

	// Encode G1 generator in Aztec format (3 copies).
	g1AztecBytes := pointToAztecG1(g1Gen)

	// Encode G2 generator in Aztec format (2 copies).
	g2AztecBytes := pointToAztecG2(g2Gen)

	// Assemble transcript.
	var buf bytes.Buffer
	buf.Write(manifest[:])
	for range numG1 {
		buf.Write(g1AztecBytes)
	}
	for range numG2 {
		buf.Write(g2AztecBytes)
	}
	// Append dummy checksum (64 bytes).
	buf.Write(make([]byte, 64))

	data := buf.Bytes()
	reader := bytes.NewReader(data)

	g1Points, tauG2, err := parseIgnitionTranscript(reader, numG1)
	if err != nil {
		t.Fatalf("parseIgnitionTranscript: %v", err)
	}

	if len(g1Points) != numG1 {
		t.Fatalf("expected %d G1 points, got %d", numG1, len(g1Points))
	}

	// Verify all parsed G1 points match the generator.
	for i, p := range g1Points {
		if !p.Equal(&g1Gen) {
			t.Errorf("G1[%d] does not match generator", i)
		}
	}

	// Verify parsed G2 point matches the generator.
	if !tauG2.Equal(&g2Gen) {
		t.Error("parsed G2 point does not match generator")
	}
}

func TestParseIgnitionTranscript_BadManifest(t *testing.T) {
	// Transcript with wrong transcript number should fail.
	var manifest [28]byte
	binary.BigEndian.PutUint32(manifest[0:4], 1) // Wrong: should be 0
	binary.BigEndian.PutUint32(manifest[16:20], 10)
	binary.BigEndian.PutUint32(manifest[20:24], 2)

	reader := bytes.NewReader(manifest[:])
	_, _, err := parseIgnitionTranscript(reader, 1)
	if err == nil {
		t.Error("expected error for wrong transcript number")
	}
}

// pointToAztecG1 encodes a G1Affine point in Aztec transcript format (64 bytes).
func pointToAztecG1(p bn254.G1Affine) []byte {
	out := make([]byte, 64)
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	stdBEToAztec(out[0:32], xBytes[:])
	stdBEToAztec(out[32:64], yBytes[:])
	return out
}

// pointToAztecG2 encodes a G2Affine point in Aztec transcript format (128 bytes).
func pointToAztecG2(p bn254.G2Affine) []byte {
	out := make([]byte, 128)
	xa0 := p.X.A0.Bytes()
	xa1 := p.X.A1.Bytes()
	ya0 := p.Y.A0.Bytes()
	ya1 := p.Y.A1.Bytes()
	stdBEToAztec(out[0:32], xa0[:])
	stdBEToAztec(out[32:64], xa1[:])
	stdBEToAztec(out[64:96], ya0[:])
	stdBEToAztec(out[96:128], ya1[:])
	return out
}

// stdBEToAztec is the inverse of aztecToStdBE (same operation -- it's an involution).
func stdBEToAztec(dst, src []byte) {
	aztecToStdBE(dst, src)
}

