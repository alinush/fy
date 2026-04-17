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

// compressedPoint returns the minimal on-wire encoding of pt. Points that
// implement CompressedBytes() (e.g., BN254 G1) use it; otherwise we fall
// back to Bytes(), which is already compressed for groups like BJJ.
func compressedPoint(pt group.Point) []byte {
	if cp, ok := pt.(interface{ CompressedBytes() []byte }); ok {
		return cp.CompressedBytes()
	}
	return pt.Bytes()
}

// serializeRound0Msg produces a canonical length-prefixed binary encoding
// of a Round0Msg that includes every field VerifyDealing checks, using
// compressed point encoding so the reported size reflects on-wire cost.
// The layout is:
//
//	SessionID [32]
//	From      uint32 BE
//	RandomMsg [32]
//	numVSS    uint32 BE, numVSS × compressed Point
//	numCts    uint32 BE, numCts × {recipientID uint32 BE, R point, z scalar}
//	IdentityProof: commitment point, challenge scalar, response scalar (inner group)
//	numProofs uint32 BE, numProofs × {recipientID uint32 BE, proofLen uint32 BE, proof bytes}
//	numDerived uint32 BE
//	  each derived curve: numVSS + numCts blocks as above, encoded in its own group
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
		out = append(out, compressedPoint(v)...)
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
		out = append(out, compressedPoint(ct.RCommitment)...)
		out = append(out, ct.EncryptedShare.Bytes()...)
	}

	out = append(out, compressedPoint(msg.IdentityProof.Commitment)...)
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

	binary.BigEndian.PutUint32(buf[:], uint32(len(msg.DerivedCurves)))
	out = append(out, buf[:]...)
	for _, dc := range msg.DerivedCurves {
		binary.BigEndian.PutUint32(buf[:], uint32(len(dc.VSSCommitments)))
		out = append(out, buf[:]...)
		for _, v := range dc.VSSCommitments {
			out = append(out, compressedPoint(v)...)
		}

		dIDs := make([]int, 0, len(dc.Ciphertexts))
		for id := range dc.Ciphertexts {
			dIDs = append(dIDs, id)
		}
		sort.Ints(dIDs)
		binary.BigEndian.PutUint32(buf[:], uint32(len(dIDs)))
		out = append(out, buf[:]...)
		for _, id := range dIDs {
			ct := dc.Ciphertexts[id]
			binary.BigEndian.PutUint32(buf[:], uint32(id))
			out = append(out, buf[:]...)
			out = append(out, compressedPoint(ct.RCommitment)...)
			out = append(out, ct.EncryptedShare.Bytes()...)
		}
	}

	return out
}

// deserializeRound0Msg parses the encoding produced by serializeRound0Msg
// using the suite's inner/outer groups for the primary fields and
// derivedGroups for any DerivedCurves. It assumes fixed per-group point and
// scalar widths derived from the Generator / a zero scalar.
func deserializeRound0Msg(
	data []byte,
	suite CurveSuite,
	derivedGroups []group.Group,
) (*Round0Msg, error) {
	outer := suite.OuterGroup()
	inner := suite.InnerGroup()
	outerPtSize := len(compressedPoint(outer.Generator()))
	innerPtSize := len(compressedPoint(inner.Generator()))
	outerScSize := len(outer.NewScalar().Bytes())
	innerScSize := len(inner.NewScalar().Bytes())

	d := &decoder{buf: data}
	msg := &Round0Msg{}

	sid, err := d.fixed(32)
	if err != nil {
		return nil, fmt.Errorf("sessionID: %w", err)
	}
	copy(msg.SessionID[:], sid)

	fromU32, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	msg.From = NodeID(fromU32)

	rnd, err := d.fixed(32)
	if err != nil {
		return nil, fmt.Errorf("randomMsg: %w", err)
	}
	copy(msg.RandomMsg[:], rnd)

	numVSS, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("numVSS: %w", err)
	}
	msg.VSSCommitments = make([]group.Point, numVSS)
	for i := range msg.VSSCommitments {
		pt, err := d.point(outer, outerPtSize)
		if err != nil {
			return nil, fmt.Errorf("vss[%d]: %w", i, err)
		}
		msg.VSSCommitments[i] = pt
	}

	numCts, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("numCts: %w", err)
	}
	msg.Ciphertexts = make(map[int]*Ciphertext, numCts)
	for i := uint32(0); i < numCts; i++ {
		recipID, err := d.u32()
		if err != nil {
			return nil, fmt.Errorf("ct[%d].id: %w", i, err)
		}
		R, err := d.point(outer, outerPtSize)
		if err != nil {
			return nil, fmt.Errorf("ct[%d].R: %w", i, err)
		}
		z, err := d.scalar(outer, outerScSize)
		if err != nil {
			return nil, fmt.Errorf("ct[%d].z: %w", i, err)
		}
		msg.Ciphertexts[int(recipID)] = &Ciphertext{RCommitment: R, EncryptedShare: z}
	}

	commit, err := d.point(inner, innerPtSize)
	if err != nil {
		return nil, fmt.Errorf("identityProof.commit: %w", err)
	}
	challenge, err := d.scalar(inner, innerScSize)
	if err != nil {
		return nil, fmt.Errorf("identityProof.challenge: %w", err)
	}
	response, err := d.scalar(inner, innerScSize)
	if err != nil {
		return nil, fmt.Errorf("identityProof.response: %w", err)
	}
	msg.IdentityProof = &IdentityProof{
		Commitment: commit,
		Challenge:  challenge,
		Response:   response,
	}

	numProofs, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("numProofs: %w", err)
	}
	msg.EVRFProofs = make(map[int][]byte, numProofs)
	for i := uint32(0); i < numProofs; i++ {
		recipID, err := d.u32()
		if err != nil {
			return nil, fmt.Errorf("proof[%d].id: %w", i, err)
		}
		proofLen, err := d.u32()
		if err != nil {
			return nil, fmt.Errorf("proof[%d].len: %w", i, err)
		}
		p, err := d.fixed(int(proofLen))
		if err != nil {
			return nil, fmt.Errorf("proof[%d].body: %w", i, err)
		}
		msg.EVRFProofs[int(recipID)] = append([]byte(nil), p...)
	}

	numDerived, err := d.u32()
	if err != nil {
		return nil, fmt.Errorf("numDerived: %w", err)
	}
	if int(numDerived) != len(derivedGroups) {
		return nil, fmt.Errorf("numDerived=%d but %d derivedGroups provided", numDerived, len(derivedGroups))
	}
	if numDerived > 0 {
		msg.DerivedCurves = make([]*DerivedCurveData, numDerived)
		for idx := uint32(0); idx < numDerived; idx++ {
			dg := derivedGroups[idx]
			dPtSize := len(compressedPoint(dg.Generator()))
			dScSize := len(dg.NewScalar().Bytes())

			numDVSS, err := d.u32()
			if err != nil {
				return nil, fmt.Errorf("derived[%d].numVSS: %w", idx, err)
			}
			vss := make([]group.Point, numDVSS)
			for i := range vss {
				pt, err := d.point(dg, dPtSize)
				if err != nil {
					return nil, fmt.Errorf("derived[%d].vss[%d]: %w", idx, i, err)
				}
				vss[i] = pt
			}

			numDCts, err := d.u32()
			if err != nil {
				return nil, fmt.Errorf("derived[%d].numCts: %w", idx, err)
			}
			cts := make(map[int]*Ciphertext, numDCts)
			for i := uint32(0); i < numDCts; i++ {
				recipID, err := d.u32()
				if err != nil {
					return nil, fmt.Errorf("derived[%d].ct[%d].id: %w", idx, i, err)
				}
				R, err := d.point(dg, dPtSize)
				if err != nil {
					return nil, fmt.Errorf("derived[%d].ct[%d].R: %w", idx, i, err)
				}
				z, err := d.scalar(dg, dScSize)
				if err != nil {
					return nil, fmt.Errorf("derived[%d].ct[%d].z: %w", idx, i, err)
				}
				cts[int(recipID)] = &Ciphertext{RCommitment: R, EncryptedShare: z}
			}

			msg.DerivedCurves[idx] = &DerivedCurveData{VSSCommitments: vss, Ciphertexts: cts}
		}
	}

	if d.remaining() != 0 {
		return nil, fmt.Errorf("trailing bytes: %d", d.remaining())
	}
	return msg, nil
}

type decoder struct {
	buf []byte
	off int
}

func (d *decoder) remaining() int { return len(d.buf) - d.off }

func (d *decoder) fixed(n int) ([]byte, error) {
	if d.remaining() < n {
		return nil, fmt.Errorf("short read: need %d have %d", n, d.remaining())
	}
	out := d.buf[d.off : d.off+n]
	d.off += n
	return out, nil
}

func (d *decoder) u32() (uint32, error) {
	b, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *decoder) point(g group.Group, size int) (group.Point, error) {
	b, err := d.fixed(size)
	if err != nil {
		return nil, err
	}
	pt, err := g.NewPoint().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (d *decoder) scalar(g group.Group, size int) (group.Scalar, error) {
	b, err := d.fixed(size)
	if err != nil {
		return nil, err
	}
	sc, err := g.NewScalar().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return sc, nil
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
// For each size it also roundtrips the transcript (serialize → deserialize →
// VerifyDealing) to confirm the encoding is complete: every field
// VerifyDealing inspects is carried on the wire with compressed point
// encoding.
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

			// Roundtrip: the reported size must cover every field VerifyDealing
			// checks. If anything is missing, verification on the reconstructed
			// message will fail.
			got, err := deserializeRound0Msg(buf, suite, cfg.DerivedGroups)
			if err != nil {
				t.Fatalf("deserializeRound0Msg: %v", err)
			}
			verifier := peers[0]
			recipientPKs := make(map[int]group.Point, n-1)
			for _, p := range peers {
				recipientPKs[p.ID] = p.PK
			}
			if err := VerifyDealing(suite, cfg, got, verifier, dealer.PK, recipientPKs); err != nil {
				t.Fatalf("VerifyDealing on deserialized transcript: %v", err)
			}
		})
	}
}

// TestTranscriptRoundtripDerived exercises the DerivedCurves branch of the
// serializer/deserializer. A single small (t=2, n=3) dealing is created with
// a BJJ derived curve, then roundtripped through serialize → deserialize and
// re-verified.
func TestTranscriptRoundtripDerived(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	inner := &bjj.BJJ{}
	suite := NewBN254BJJSuite()
	bjjGroup := &bjj.BJJ{}

	n, threshold := 3, 2
	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	cfg := &DkgConfig{
		N:             n,
		T:             threshold,
		SessionID:     sid,
		DerivedGroups: []group.Group{bjjGroup},
	}
	participants := makeParticipants(t, inner, n)
	dealer := participants[0]
	peers := participants[1:]

	dealing, err := CreateDealing(suite, cfg, dealer, peers, rand.Reader)
	if err != nil {
		t.Fatalf("CreateDealing: %v", err)
	}

	buf := serializeRound0Msg(dealing.Message)
	t.Logf("transcript (1 derived curve) bytes=%d", len(buf))

	got, err := deserializeRound0Msg(buf, suite, cfg.DerivedGroups)
	if err != nil {
		t.Fatalf("deserializeRound0Msg: %v", err)
	}
	recipientPKs := make(map[int]group.Point, n-1)
	for _, p := range peers {
		recipientPKs[p.ID] = p.PK
	}
	if err := VerifyDealing(suite, cfg, got, peers[0], dealer.PK, recipientPKs); err != nil {
		t.Fatalf("VerifyDealing on deserialized transcript: %v", err)
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
