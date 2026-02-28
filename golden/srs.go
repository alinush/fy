package golden

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

const (
	ignitionTranscriptURL  = "https://aztec-ignition.s3.eu-west-2.amazonaws.com/MAIN+IGNITION/sealed/transcript00.dat"
	ignitionTranscriptFile = "transcript00.dat"
	srsCanonicalFile       = "srs_canonical.bin"
	srsLagrangeFile        = "srs_lagrange.bin"

	ignitionManifestSize = 28  // bytes
	ignitionG1PointSize  = 64  // uncompressed: 32 X + 32 Y
	ignitionG2PointSize  = 128 // uncompressed: 4 × 32 Fp elements

	// Expected size of transcript00.dat: 28-byte manifest + 5,040,000 G1 points
	// (64 bytes each) + 2 G2 points (128 bytes each) + 64-byte checksum.
	ignitionTranscriptExpectedSize = 28 + 5_040_000*64 + 2*128 + 64

	// maxSRSG1Points caps the number of G1 points we will allocate.
	maxSRSG1Points = 1 << 23 // ~8M, well above any practical circuit size

	// maxTranscriptSize is the hard cap on download body size.
	maxTranscriptSize = 500 << 20 // 500 MB

	defaultCacheDir = ".cache/fy/srs" // relative to $HOME
)

// srsHTTPClient is used for downloading the transcript.
// Configured with a timeout and HTTPS-only redirect policy.
var srsHTTPClient = &http.Client{
	Timeout: 10 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL.Scheme)
		}
		return nil
	},
}

// LoadCeremonySRS loads or downloads the Aztec Ignition ceremony SRS
// sized for the given constraint system. Caches gnark-format SRS files
// under cacheDir for fast subsequent loads.
func LoadCeremonySRS(ccs constraint.ConstraintSystem) (canonical, lagrange kzg.SRS, err error) {
	sizeCanonical, sizeLagrange := plonk.SRSSize(ccs)

	cacheDir, err := resolveCacheDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving cache dir: %w", err)
	}

	// Try loading cached gnark SRS files.
	canonicalSRS, lagrangeSRS, cacheErr := loadCachedSRS(cacheDir, sizeCanonical, sizeLagrange)
	if cacheErr != nil {
		// Load or download the raw Aztec transcript.
		transcriptPath := filepath.Join(cacheDir, ignitionTranscriptFile)
		if _, statErr := os.Stat(transcriptPath); os.IsNotExist(statErr) {
			if dlErr := downloadTranscript(transcriptPath); dlErr != nil {
				return nil, nil, fmt.Errorf("downloading transcript: %w", dlErr)
			}
		}

		// Parse transcript.
		f, openErr := os.Open(transcriptPath)
		if openErr != nil {
			return nil, nil, fmt.Errorf("opening transcript: %w", openErr)
		}
		defer f.Close()

		// We need sizeCanonical - 1 G1 points (τ^1 through τ^(sizeCanonical-1)).
		g1Points, tauG2, parseErr := parseIgnitionTranscript(f, sizeCanonical-1)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parsing transcript: %w", parseErr)
		}

		// Build canonical SRS.
		canonicalSRS, err = buildCanonicalSRS(g1Points, tauG2, sizeCanonical)
		if err != nil {
			return nil, nil, fmt.Errorf("building canonical SRS: %w", err)
		}

		// Compute Lagrange form.
		lagrangeG1, lagErr := kzg_bn254.ToLagrangeG1(canonicalSRS.Pk.G1[:sizeLagrange])
		if lagErr != nil {
			return nil, nil, fmt.Errorf("computing Lagrange SRS: %w", lagErr)
		}

		lagrangeSRS = &kzg_bn254.SRS{
			Pk: kzg_bn254.ProvingKey{G1: lagrangeG1},
			Vk: canonicalSRS.Vk,
		}

		// Cache for next time.
		if cacheWriteErr := cacheSRS(cacheDir, canonicalSRS, lagrangeSRS); cacheWriteErr != nil {
			fmt.Fprintf(os.Stderr, "golden: warning: failed to cache SRS: %v\n", cacheWriteErr)
		}
	}

	// Always verify SRS consistency (both fresh and cached paths).
	if err := verifySRSConsistency(canonicalSRS); err != nil {
		return nil, nil, fmt.Errorf("SRS consistency check failed: %w", err)
	}

	return canonicalSRS, lagrangeSRS, nil
}

// resolveCacheDir returns the SRS cache directory, creating it if needed.
func resolveCacheDir() (string, error) {
	dir := os.Getenv("FY_SRS_CACHE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("getting home dir: %w", err)
		}
		dir = filepath.Join(home, defaultCacheDir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	return dir, nil
}

// loadCachedSRS attempts to load pre-cached gnark-format SRS files.
func loadCachedSRS(cacheDir string, sizeCanonical, sizeLagrange int) (*kzg_bn254.SRS, *kzg_bn254.SRS, error) {
	canonicalPath := filepath.Join(cacheDir, srsCanonicalFile)
	lagrangePath := filepath.Join(cacheDir, srsLagrangeFile)

	canonicalSRS := &kzg_bn254.SRS{}
	lagrangeSRS := &kzg_bn254.SRS{}

	cf, err := os.Open(canonicalPath)
	if err != nil {
		return nil, nil, err
	}
	defer cf.Close()

	if _, err := canonicalSRS.ReadFrom(cf); err != nil {
		return nil, nil, fmt.Errorf("reading cached canonical SRS: %w", err)
	}

	lf, err := os.Open(lagrangePath)
	if err != nil {
		return nil, nil, err
	}
	defer lf.Close()

	if _, err := lagrangeSRS.ReadFrom(lf); err != nil {
		return nil, nil, fmt.Errorf("reading cached lagrange SRS: %w", err)
	}

	// Validate sizes.
	if len(canonicalSRS.Pk.G1) < sizeCanonical {
		return nil, nil, fmt.Errorf("cached canonical SRS too small: got %d, need %d", len(canonicalSRS.Pk.G1), sizeCanonical)
	}
	if len(lagrangeSRS.Pk.G1) < sizeLagrange {
		return nil, nil, fmt.Errorf("cached lagrange SRS too small: got %d, need %d", len(lagrangeSRS.Pk.G1), sizeLagrange)
	}

	return canonicalSRS, lagrangeSRS, nil
}

// cacheSRS saves gnark-format SRS files atomically using temp+rename.
func cacheSRS(cacheDir string, canonical, lagrange *kzg_bn254.SRS) error {
	canonicalPath := filepath.Join(cacheDir, srsCanonicalFile)
	lagrangePath := filepath.Join(cacheDir, srsLagrangeFile)

	if err := writeFileAtomic(canonicalPath, func(w io.Writer) error {
		_, err := canonical.WriteTo(w)
		return err
	}); err != nil {
		return fmt.Errorf("writing canonical SRS: %w", err)
	}

	if err := writeFileAtomic(lagrangePath, func(w io.Writer) error {
		_, err := lagrange.WriteTo(w)
		return err
	}); err != nil {
		os.Remove(canonicalPath) // clean up partial cache
		return fmt.Errorf("writing lagrange SRS: %w", err)
	}

	return nil
}

// writeFileAtomic writes to a temp file and atomically renames on success.
func writeFileAtomic(path string, writeFn func(io.Writer) error) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // no-op if already renamed
	}()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}

	if err := writeFn(tmpFile); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

// parseIgnitionTranscript reads G1 and G2 points from an Aztec Ignition
// transcript file. Returns exactly numG1 G1 points (τ^1 through τ^numG1)
// and the τ·G2 point from the G2 section.
//
// Manifest layout (28 bytes, all fields big-endian uint32):
//
//	[0:4]   TranscriptNumber
//	[4:8]   TotalTranscripts
//	[8:12]  TotalG1Points
//	[12:16] TotalG2Points
//	[16:20] NumG1Points (local)
//	[20:24] NumG2Points (local)
//	[24:28] StartFrom
func parseIgnitionTranscript(r io.ReaderAt, numG1 int) ([]bn254.G1Affine, bn254.G2Affine, error) {
	var tauG2 bn254.G2Affine

	if numG1 > maxSRSG1Points {
		return nil, tauG2, fmt.Errorf("numG1 %d exceeds maximum %d", numG1, maxSRSG1Points)
	}

	// Read and validate manifest header (28 bytes).
	var manifest [ignitionManifestSize]byte
	if _, err := r.ReadAt(manifest[:], 0); err != nil {
		return nil, tauG2, fmt.Errorf("reading manifest: %w", err)
	}

	transcriptNum := binary.BigEndian.Uint32(manifest[0:4])
	// totalTranscripts := binary.BigEndian.Uint32(manifest[4:8])
	// totalG1Points := binary.BigEndian.Uint32(manifest[8:12])
	// totalG2Points := binary.BigEndian.Uint32(manifest[12:16])
	numG1Points := binary.BigEndian.Uint32(manifest[16:20])
	numG2Points := binary.BigEndian.Uint32(manifest[20:24])
	// startFrom := binary.BigEndian.Uint32(manifest[24:28])

	if transcriptNum != 0 {
		return nil, tauG2, fmt.Errorf("expected transcript 0, got %d", transcriptNum)
	}
	if int(numG1Points) < numG1 {
		return nil, tauG2, fmt.Errorf("transcript has %d G1 points, need %d", numG1Points, numG1)
	}
	if numG2Points < 2 {
		return nil, tauG2, fmt.Errorf("transcript has %d G2 points, need at least 2", numG2Points)
	}

	// Parse G1 points.
	g1Points := make([]bn254.G1Affine, numG1)
	g1Buf := make([]byte, ignitionG1PointSize)
	var stdBE [32]byte

	for i := range numG1 {
		offset := int64(ignitionManifestSize) + int64(i)*int64(ignitionG1PointSize)
		if _, err := r.ReadAt(g1Buf, offset); err != nil {
			return nil, tauG2, fmt.Errorf("reading G1 point %d: %w", i, err)
		}

		// Convert X coordinate.
		aztecToStdBE(stdBE[:], g1Buf[0:32])
		if err := g1Points[i].X.SetBytesCanonical(stdBE[:]); err != nil {
			return nil, tauG2, fmt.Errorf("G1[%d] X: %w", i, err)
		}

		// Convert Y coordinate.
		aztecToStdBE(stdBE[:], g1Buf[32:64])
		if err := g1Points[i].Y.SetBytesCanonical(stdBE[:]); err != nil {
			return nil, tauG2, fmt.Errorf("G1[%d] Y: %w", i, err)
		}

		if !g1Points[i].IsOnCurve() {
			return nil, tauG2, fmt.Errorf("G1[%d] not on curve", i)
		}
	}

	// Parse G2 section: τ·G2 is the first G2 point.
	g2Offset := int64(ignitionManifestSize) + int64(numG1Points)*int64(ignitionG1PointSize)
	g2Buf := make([]byte, ignitionG2PointSize)
	if _, err := r.ReadAt(g2Buf, g2Offset); err != nil {
		return nil, tauG2, fmt.Errorf("reading G2 point: %w", err)
	}

	// G2 point: X = (A0, A1) in Fp2, Y = (A0, A1) in Fp2.
	// Each component is 32 bytes in Aztec encoding.
	aztecToStdBE(stdBE[:], g2Buf[0:32])
	if err := tauG2.X.A0.SetBytesCanonical(stdBE[:]); err != nil {
		return nil, tauG2, fmt.Errorf("G2 X.A0: %w", err)
	}
	aztecToStdBE(stdBE[:], g2Buf[32:64])
	if err := tauG2.X.A1.SetBytesCanonical(stdBE[:]); err != nil {
		return nil, tauG2, fmt.Errorf("G2 X.A1: %w", err)
	}
	aztecToStdBE(stdBE[:], g2Buf[64:96])
	if err := tauG2.Y.A0.SetBytesCanonical(stdBE[:]); err != nil {
		return nil, tauG2, fmt.Errorf("G2 Y.A0: %w", err)
	}
	aztecToStdBE(stdBE[:], g2Buf[96:128])
	if err := tauG2.Y.A1.SetBytesCanonical(stdBE[:]); err != nil {
		return nil, tauG2, fmt.Errorf("G2 Y.A1: %w", err)
	}

	if !tauG2.IsInSubGroup() {
		return nil, tauG2, fmt.Errorf("G2 point not in subgroup")
	}

	return g1Points, tauG2, nil
}

// aztecToStdBE converts a 32-byte Aztec-encoded field element (uint64[4],
// least-significant word first, each word big-endian) to standard big-endian.
func aztecToStdBE(dst, src []byte) {
	// Swap 8-byte words: [w0][w1][w2][w3] → [w3][w2][w1][w0].
	copy(dst[0:8], src[24:32])
	copy(dst[8:16], src[16:24])
	copy(dst[16:24], src[8:16])
	copy(dst[24:32], src[0:8])
}

// buildCanonicalSRS constructs a gnark kzg_bn254.SRS from parsed transcript data.
func buildCanonicalSRS(g1Powers []bn254.G1Affine, tauG2 bn254.G2Affine, sizeCanonical int) (*kzg_bn254.SRS, error) {
	_, _, g1Gen, g2Gen := bn254.Generators()

	srs := &kzg_bn254.SRS{
		Pk: kzg_bn254.ProvingKey{
			G1: make([]bn254.G1Affine, sizeCanonical),
		},
	}

	// Pk.G1[0] = G1 generator (τ^0 · G1).
	srs.Pk.G1[0].Set(&g1Gen)

	// Pk.G1[1:] = parsed G1 points (τ^1 through τ^(sizeCanonical-1)).
	if len(g1Powers) < sizeCanonical-1 {
		return nil, fmt.Errorf("need %d G1 points, got %d", sizeCanonical-1, len(g1Powers))
	}
	copy(srs.Pk.G1[1:], g1Powers[:sizeCanonical-1])

	// Verifying key.
	srs.Vk.G1.Set(&g1Gen)
	srs.Vk.G2[0].Set(&g2Gen)
	srs.Vk.G2[1].Set(&tauG2)

	// Precompute pairing lines.
	srs.Vk.Lines[0] = bn254.PrecomputeLines(srs.Vk.G2[0])
	srs.Vk.Lines[1] = bn254.PrecomputeLines(srs.Vk.G2[1])

	return srs, nil
}

// verifySRSConsistency verifies that all G1 powers in the SRS are consistent
// with the G2 elements via a batched random pairing check.
//
// For each consecutive pair we require:
//
//	e(G1[i+1], G2) = e(G1[i], τ·G2)
//
// Using a random linear combination with challenge r, this reduces to:
//
//	e(Σ r^i·G1[i+1], G2) · e(-Σ r^i·G1[i], τ·G2) = 1
//
// which verifies all n-1 relationships in a single multi-pairing.
func verifySRSConsistency(srs *kzg_bn254.SRS) error {
	n := len(srs.Pk.G1)
	if n < 2 {
		return fmt.Errorf("SRS too small: need at least 2 G1 points, got %d", n)
	}

	// Random challenge for Schwartz-Zippel batch verification.
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		return fmt.Errorf("generating random challenge: %w", err)
	}

	config := ecc.MultiExpConfig{}

	// L = fold(G1[1:], r) = Σ r^i · G1[i+1]
	var L bn254.G1Affine
	if _, err := L.Fold(srs.Pk.G1[1:], r, config); err != nil {
		return fmt.Errorf("computing L: %w", err)
	}

	// R = fold(G1[:n-1], r) = Σ r^i · G1[i]
	var R bn254.G1Affine
	if _, err := R.Fold(srs.Pk.G1[:n-1], r, config); err != nil {
		return fmt.Errorf("computing R: %w", err)
	}

	// Check: e(L, G2) · e(-R, τ·G2) = 1
	var negR bn254.G1Affine
	negR.Neg(&R)

	check, err := bn254.Pair(
		[]bn254.G1Affine{L, negR},
		[]bn254.G2Affine{srs.Vk.G2[0], srs.Vk.G2[1]},
	)
	if err != nil {
		return fmt.Errorf("pairing computation: %w", err)
	}

	var one bn254.GT
	one.SetOne()
	if !check.Equal(&one) {
		return fmt.Errorf("batch pairing check failed: SRS powers are inconsistent")
	}

	return nil
}

// downloadTranscript downloads the Aztec Ignition transcript to dstPath.
func downloadTranscript(dstPath string) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "golden: downloading Aztec Ignition ceremony transcript\n")

	resp, err := srsHTTPClient.Get(ignitionTranscriptURL)
	if err != nil {
		return fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Validate content length if provided.
	if resp.ContentLength > 0 {
		if resp.ContentLength < 1<<20 {
			return fmt.Errorf("transcript too small: %d bytes", resp.ContentLength)
		}
		if resp.ContentLength > maxTranscriptSize {
			return fmt.Errorf("transcript too large: %d bytes", resp.ContentLength)
		}
	}

	// Hard-cap the response body regardless of Content-Length header.
	limitedBody := io.LimitReader(resp.Body, maxTranscriptSize+1)

	// Stream to temp file, rename on success.
	tmpFile, err := os.CreateTemp(filepath.Dir(dstPath), filepath.Base(dstPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	closed := false
	defer func() {
		if !closed {
			tmpFile.Close()
		}
		os.Remove(tmpPath) // no-op if already renamed
	}()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting temp file permissions: %w", err)
	}

	var written int64
	total := resp.ContentLength
	lastPct := -1

	buf := make([]byte, 1<<20) // 1 MB buffer
	for {
		n, readErr := limitedBody.Read(buf)
		if n > 0 {
			if _, wErr := tmpFile.Write(buf[:n]); wErr != nil {
				return fmt.Errorf("writing transcript: %w", wErr)
			}
			written += int64(n)

			// Enforce hard cap on written bytes.
			if written > maxTranscriptSize {
				return fmt.Errorf("transcript exceeds maximum size of %d bytes", maxTranscriptSize)
			}

			if total > 0 {
				pct := int(written * 100 / total)
				if pct/10 > lastPct/10 {
					fmt.Fprintf(os.Stderr, "golden: download progress: %d%%\n", pct)
					lastPct = pct
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading response: %w", readErr)
		}
	}

	// Validate downloaded file size against expected size.
	if written != ignitionTranscriptExpectedSize {
		return fmt.Errorf("unexpected transcript size: got %d bytes, expected %d", written, ignitionTranscriptExpectedSize)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	closed = true

	if err := os.Rename(tmpPath, dstPath); err != nil {
		return fmt.Errorf("renaming transcript: %w", err)
	}

	fmt.Fprintf(os.Stderr, "golden: transcript downloaded (%d bytes)\n", written)
	return nil
}
