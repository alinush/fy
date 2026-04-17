package golden

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

// benchSizes are the (t, n) pairs benchmarked in the blog post's
// "Full benchmarks" table for the Chunky/Groth21 PVSS comparison.
// Override via GOLDEN_SIZES="t:n,t:n,..." to run a custom subset.
var benchSizes = [][2]int{
	{6, 8},
	{11, 16},
	{22, 32},
	{43, 64},
	{85, 128},
	{169, 256},
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

// serializeRound0Msg produces a canonical length-prefixed binary encoding
// of a Round0Msg, used to report on-wire transcript size. The layout is:
//
//	SessionID [32]
//	From      uint32 BE
//	RandomMsg [32]
//	numVSS    uint32 BE, numVSS × Point.Bytes()
//	numCts    uint32 BE, numCts × {recipientID uint32 BE, R point, z scalar}
//	IdentityProof: commitment point, challenge scalar, response scalar
//	numProofs uint32 BE, numProofs × {recipientID uint32 BE, proofLen uint32 BE, proof bytes}
func serializeRound0Msg(msg *Round0Msg) []byte {
	out := make([]byte, 0, 4096)

	out = append(out, msg.SessionID[:]...)

	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(msg.From))
	out = append(out, buf[:]...)

	out = append(out, msg.RandomMsg[:]...)

	binary.BigEndian.PutUint32(buf[:], uint32(len(msg.VSSCommitments)))
	out = append(out, buf[:]...)
	for _, v := range msg.VSSCommitments {
		out = append(out, v.Bytes()...)
	}

	ctIDs := make([]int, 0, len(msg.Ciphertexts))
	for id := range msg.Ciphertexts {
		ctIDs = append(ctIDs, id)
	}
	sort.Ints(ctIDs)
	binary.BigEndian.PutUint32(buf[:], uint32(len(ctIDs)))
	out = append(out, buf[:]...)
	for _, id := range ctIDs {
		ct := msg.Ciphertexts[id]
		binary.BigEndian.PutUint32(buf[:], uint32(id))
		out = append(out, buf[:]...)
		out = append(out, ct.RCommitment.Bytes()...)
		out = append(out, ct.EncryptedShare.Bytes()...)
	}

	out = append(out, msg.IdentityProof.Commitment.Bytes()...)
	out = append(out, msg.IdentityProof.Challenge.Bytes()...)
	out = append(out, msg.IdentityProof.Response.Bytes()...)

	prIDs := make([]int, 0, len(msg.EVRFProofs))
	for id := range msg.EVRFProofs {
		prIDs = append(prIDs, id)
	}
	sort.Ints(prIDs)
	binary.BigEndian.PutUint32(buf[:], uint32(len(prIDs)))
	out = append(out, buf[:]...)
	for _, id := range prIDs {
		p := msg.EVRFProofs[id]
		binary.BigEndian.PutUint32(buf[:], uint32(id))
		out = append(out, buf[:]...)
		binary.BigEndian.PutUint32(buf[:], uint32(len(p)))
		out = append(out, buf[:]...)
		out = append(out, p...)
	}

	return out
}

// makeParticipants generates N participants with fresh BJJ key pairs.
func makeParticipants(tb testing.TB, inner group.Group, n int) []*Participant {
	tb.Helper()
	out := make([]*Participant, n)
	for i := 0; i < n; i++ {
		sk, err := inner.RandomScalar(rand.Reader)
		if err != nil {
			tb.Fatalf("sk %d: %v", i+1, err)
		}
		pk := inner.NewPoint().ScalarMult(sk, inner.Generator())
		out[i] = &Participant{ID: i + 1, SK: sk, PK: pk}
	}
	return out
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
		cfg := &DkgConfig{N: 2, T: 2, SessionID: sid}
		ps := makeParticipants(tb, inner, 2)
		if _, err := CreateDealing(suite, cfg, ps[0], []*Participant{ps[1]}, rand.Reader); err != nil {
			tb.Fatalf("warmup CreateDealing: %v", err)
		}
	})
}

// TestPrintTranscriptSize reports the serialized size of one Round0Msg for
// each (t, n) configured via GOLDEN_SIZES (default: the blog's full table).
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
			cfg := &DkgConfig{N: n, T: threshold, SessionID: sid}
			participants := makeParticipants(t, inner, n)
			dealer := participants[0]
			peers := participants[1:]

			dealing, err := CreateDealing(suite, cfg, dealer, peers, rand.Reader)
			if err != nil {
				t.Fatalf("CreateDealing: %v", err)
			}
			buf := serializeRound0Msg(dealing.Message)
			t.Logf("transcript t=%-3d n=%-3d bytes=%-9d (%.2f KiB)",
				threshold, n, len(buf), float64(len(buf))/1024)
		})
	}
}

// TestPrintBenchmarks runs a full end-to-end measurement of Deal, Verify,
// Serialize, and Decrypt-share for each (t, n) from GOLDEN_SIZES (default:
// the blog's full table) and prints one markdown-friendly row per size.
// The setup dealing is reused across the latter three measurements so the
// expensive (>1 minute at n=256) PLONK proving cost is only paid once per
// size.
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
		// Subtests make each size's output stream as it completes under -v.
		t.Run(fmt.Sprintf("t=%d,n=%d", threshold, n), func(t *testing.T) {
			var sid SessionID
			if _, err := rand.Read(sid[:]); err != nil {
				t.Fatal(err)
			}
			cfg := &DkgConfig{N: n, T: threshold, SessionID: sid}
			participants := makeParticipants(t, inner, n)
			dealer := participants[0]
			peers := participants[1:]

			// --- Deal ---
			dealStart := time.Now()
			dealing, err := CreateDealing(suite, cfg, dealer, peers, rand.Reader)
			if err != nil {
				t.Fatalf("CreateDealing: %v", err)
			}
			dealMs := msSince(dealStart)

			// --- Verify (arbitrary recipient verifying the dealer's transcript) ---
			verifier := peers[0]
			recipientPKs := make(map[int]group.Point, n-1)
			for _, p := range peers {
				recipientPKs[p.ID] = p.PK
			}
			verStart := time.Now()
			if err := VerifyDealing(suite, cfg, dealing.Message, verifier, dealer.PK, recipientPKs); err != nil {
				t.Fatalf("VerifyDealing: %v", err)
			}
			verifyMs := msSince(verStart)

			// --- Serialize (average over many iters; cheap) ---
			serIters := 2000
			var serBuf []byte
			serStart := time.Now()
			for i := 0; i < serIters; i++ {
				serBuf = serializeRound0Msg(dealing.Message)
			}
			serMs := msSince(serStart) / float64(serIters)
			sizeBytes := len(serBuf)

			// --- Decrypt-share (per-dealing recipient work: re-derive pad + subtract) ---
			outer := suite.OuterGroup()
			alpha, err := outer.HashToScalar([]byte(lhlAlphaDomain), cfg.SessionID[:])
			if err != nil {
				t.Fatal(err)
			}
			sessionData := [][]byte{cfg.SessionID[:], dealing.Message.RandomMsg[:]}
			recipient := peers[0]
			ct := dealing.Message.Ciphertexts[recipient.ID]

			decIters := 500
			decStart := time.Now()
			for i := 0; i < decIters; i++ {
				padResult, err := DerivePad(suite, recipient.SK, dealer.PK, sessionData, alpha)
				if err != nil {
					t.Fatal(err)
				}
				share := outer.NewScalar().Sub(ct.EncryptedShare, padResult.Pad)
				_ = share
				padResult.Pad.Zero()
			}
			decMs := msSince(decStart) / float64(decIters)

			// Print one row per subtest so results stream under -v.
			fmt.Printf("%-4d %-4d %10d %12.2f %14.2f %16.3f %18.3f\n",
				threshold, n, sizeBytes, dealMs, verifyMs, serMs, decMs)
		})
	}
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1e6
}
