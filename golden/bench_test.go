package golden

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

// benchSizes are the (t, n) pairs benchmarked in the blog post's
// "Full benchmarks" table for the Chunky/Groth21/Golden PVSS comparison.
// Override via GOLDEN_SIZES="t:n,t:n,..." to run a custom subset.
var benchSizes = [][2]int{
	{3, 4},
	{6, 8},
	{11, 16},
	{22, 32},
	{43, 64},
	{86, 128},
	{171, 256},
	{342, 512},
	{683, 1024},
}

// sizesFromEnv returns benchSizes or an override parsed from GOLDEN_SIZES.
// The override format is a comma-separated list of "t:n" pairs.
func sizesFromEnv() [][2]int {
	v := os.Getenv("GOLDEN_SIZES")
	if v == "" {
		return benchSizes
	}
	var out [][2]int
	for _, part := range strings.Split(v, ",") {
		tn := strings.SplitN(strings.TrimSpace(part), ":", 2)
		if len(tn) != 2 {
			panic("GOLDEN_SIZES must be a comma list of t:n, got " + part)
		}
		t, err := strconv.Atoi(strings.TrimSpace(tn[0]))
		if err != nil {
			panic("GOLDEN_SIZES: bad t: " + err.Error())
		}
		n, err := strconv.Atoi(strings.TrimSpace(tn[1]))
		if err != nil {
			panic("GOLDEN_SIZES: bad n: " + err.Error())
		}
		out = append(out, [2]int{t, n})
	}
	return out
}

// makePlayers generates n participants with fresh inner-group key pairs and
// sequential IDs 1..n. Used by both PVSSDeal and VerifyDealing benches.
func makePlayers(tb testing.TB, inner group.Group, n int) []*Participant {
	tb.Helper()
	out := make([]*Participant, n)
	for i := 0; i < n; i++ {
		sk, err := inner.RandomScalar(rand.Reader)
		if err != nil {
			tb.Fatalf("player %d sk: %v", i+1, err)
		}
		pk := inner.NewPoint().ScalarMult(sk, inner.Generator())
		out[i] = &Participant{ID: i + 1, SK: sk, PK: pk}
	}
	return out
}

// makeDealer generates a fresh key pair independent of the n players.
// Its ID is n+1 so that it never collides with any player ID.
func makeDealer(tb testing.TB, inner group.Group, n int) *Participant {
	tb.Helper()
	sk, err := inner.RandomScalar(rand.Reader)
	if err != nil {
		tb.Fatalf("dealer sk: %v", err)
	}
	pk := inner.NewPoint().ScalarMult(sk, inner.Generator())
	return &Participant{ID: n + 1, SK: sk, PK: pk}
}

// warmupOnce compiles the eVRF circuit and materializes PLONK keys so they
// do not bias the first timed measurement. Runs once per test binary.
var warmupOnce sync.Once

func doWarmup(tb testing.TB) {
	warmupOnce.Do(func() {
		tb.Helper()
		inner := &bjj.BJJ{}
		suite := NewBN254BJJSuite()
		var sid SessionID
		if _, err := rand.Read(sid[:]); err != nil {
			tb.Fatalf("warmup sid: %v", err)
		}
		cfg := &PVSSConfig{N: 2, T: 2, SessionID: sid}
		players := makePlayers(tb, inner, 2)
		dealer := makeDealer(tb, inner, 2)
		if _, err := PVSSDeal(suite, cfg, dealer, players, rand.Reader); err != nil {
			tb.Fatalf("warmup PVSSDeal: %v", err)
		}
	})
}

// playerPKsOf returns player PKs in ID order, matching the convention used
// by PVSSVerify / PVSSTranscript.Ciphertexts[i-1].
func playerPKsOf(players []*Participant) []group.Point {
	out := make([]group.Point, len(players))
	for _, p := range players {
		out[p.ID-1] = p.PK
	}
	return out
}

// TestPrintTranscriptSize reports the on-wire size of one Golden PVSS
// transcript for each (t, n) configured via GOLDEN_SIZES (default: the blog's
// full table). For each size it also performs a full roundtrip (deal →
// serialize → deserialize → verify) to confirm the encoding carries every
// field PVSSVerify checks, using compressed point encoding throughout.
//
// Example:
//
//	go test ./golden/ -run TestPrintTranscriptSize -v
//	GOLDEN_SIZES=6:8,11:16 go test ./golden/ -run TestPrintTranscriptSize -v
func TestPrintTranscriptSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	inner := &bjj.BJJ{}
	suite := NewBN254BJJSuite()

	for _, s := range sizesFromEnv() {
		threshold, n := s[0], s[1]
		t.Run(fmt.Sprintf("t=%d,n=%d", threshold, n), func(t *testing.T) {
			var sid SessionID
			if _, err := rand.Read(sid[:]); err != nil {
				t.Fatal(err)
			}
			cfg := &PVSSConfig{N: n, T: threshold, SessionID: sid}
			players := makePlayers(t, inner, n)
			dealer := makeDealer(t, inner, n)

			trs, err := PVSSDeal(suite, cfg, dealer, players, rand.Reader)
			if err != nil {
				t.Fatalf("PVSSDeal: %v", err)
			}
			buf, err := trs.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			t.Logf("transcript t=%-3d n=%-3d bytes=%-9d (%.2f KiB)",
				threshold, n, len(buf), float64(len(buf))/1024)

			// Roundtrip: the reported size must cover every field PVSSVerify
			// checks. If anything is missing, verification on the reconstructed
			// transcript will fail.
			got, err := DeserializePVSSTranscript(buf, suite, cfg)
			if err != nil {
				t.Fatalf("DeserializePVSSTranscript: %v", err)
			}
			if err := PVSSVerify(suite, cfg, got, dealer.PK, playerPKsOf(players)); err != nil {
				t.Fatalf("PVSSVerify on deserialized transcript: %v", err)
			}
		})
	}
}

// TestPrintBenchmarks runs a full end-to-end measurement of Deal, Verify,
// Serialize, and Decrypt-share for each (t, n) from GOLDEN_SIZES (default:
// the blog's full table) and prints one markdown-friendly row per size.
// The setup dealing is reused across the latter three measurements so the
// expensive PLONK proving cost (~1.2 s per recipient; >20 minutes at n=1024)
// is only paid once per size.
//
// Example:
//
//	go test ./golden/ -run TestPrintBenchmarks -v -timeout 2h
//	GOLDEN_SIZES=6:8,11:16 go test ./golden/ -run TestPrintBenchmarks -v
func TestPrintBenchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	inner := &bjj.BJJ{}
	suite := NewBN254BJJSuite()

	fmt.Printf("\n%-4s %-4s %10s %12s %14s %16s %18s\n",
		"t", "n", "size(B)", "deal (ms)", "verify (ms)", "serialize (ms)", "decrypt-share (ms)")

	for _, s := range sizesFromEnv() {
		threshold, n := s[0], s[1]
		t.Run(fmt.Sprintf("t=%d,n=%d", threshold, n), func(t *testing.T) {
			var sid SessionID
			if _, err := rand.Read(sid[:]); err != nil {
				t.Fatal(err)
			}
			cfg := &PVSSConfig{N: n, T: threshold, SessionID: sid}
			players := makePlayers(t, inner, n)
			dealer := makeDealer(t, inner, n)
			playerPKs := playerPKsOf(players)

			// --- Deal ---
			dealStart := time.Now()
			trs, err := PVSSDeal(suite, cfg, dealer, players, rand.Reader)
			if err != nil {
				t.Fatalf("PVSSDeal: %v", err)
			}
			dealMs := msSince(dealStart)

			// --- Verify ---
			verStart := time.Now()
			if err := PVSSVerify(suite, cfg, trs, dealer.PK, playerPKs); err != nil {
				t.Fatalf("PVSSVerify: %v", err)
			}
			verifyMs := msSince(verStart)

			// --- Serialize (average over many iters; cheap) ---
			serIters := 2000
			var serBuf []byte
			serStart := time.Now()
			for i := 0; i < serIters; i++ {
				serBuf, err = trs.Serialize()
				if err != nil {
					t.Fatal(err)
				}
			}
			serMs := msSince(serStart) / float64(serIters)
			sizeBytes := len(serBuf)

			// --- Decrypt-share (per-player work) ---
			// Pick player 1; measurement is independent of which player.
			player := players[0]
			decIters := 500
			decStart := time.Now()
			for i := 0; i < decIters; i++ {
				share, err := PVSSDecryptShare(suite, cfg, trs, player.ID, player.SK, dealer.PK)
				if err != nil {
					t.Fatal(err)
				}
				share.Zero()
			}
			decMs := msSince(decStart) / float64(decIters)

			fmt.Printf("%-4d %-4d %10d %12.2f %14.2f %16.3f %18.3f\n",
				threshold, n, sizeBytes, dealMs, verifyMs, serMs, decMs)
		})
	}
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1e6
}
