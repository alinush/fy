package golden

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/group"
)

// pvssFixture materialises a minimal (t=2, n=3) PVSS test setup: suite,
// config, a dealer with its own key pair, three players with distinct IDs
// 1..3, and the corresponding ordered playerPKs slice that PVSSVerify expects.
type pvssFixture struct {
	suite     CurveSuite
	inner     group.Group
	cfg       *PVSSConfig
	dealer    *Participant
	players   []*Participant
	playerPKs []group.Point
}

func newPVSSFixture(tb testing.TB, n, t int) *pvssFixture {
	tb.Helper()
	inner := &bjj.BJJ{}
	suite := NewBN254BJJSuite()
	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		tb.Fatalf("sid: %v", err)
	}
	players := makePlayers(tb, inner, n)
	dealer := makeDealer(tb, inner, n)
	return &pvssFixture{
		suite:     suite,
		inner:     inner,
		cfg:       &PVSSConfig{N: n, T: t, SessionID: sid},
		dealer:    dealer,
		players:   players,
		playerPKs: playerPKsOf(players),
	}
}

// TestPVSSDealVerify is the basic happy path: a dealt transcript verifies
// against the correct dealerPK and playerPKs.
func TestPVSSDealVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("PVSSDeal: %v", err)
	}
	if got := len(trs.VSSCommitments); got != f.cfg.T {
		t.Errorf("len(VSSCommitments)=%d, want T=%d", got, f.cfg.T)
	}
	if got := len(trs.Ciphertexts); got != f.cfg.N {
		t.Errorf("len(Ciphertexts)=%d, want N=%d", got, f.cfg.N)
	}
	if got := len(trs.EVRFProofs); got != f.cfg.N {
		t.Errorf("len(EVRFProofs)=%d, want N=%d", got, f.cfg.N)
	}
	if err := PVSSVerify(f.suite, f.cfg, trs, f.dealer.PK, f.playerPKs); err != nil {
		t.Fatalf("PVSSVerify: %v", err)
	}
}

// TestPVSSSerializeRoundtrip: deal → serialize → deserialize → verify must
// pass and produce a byte-identical re-serialization.
func TestPVSSSerializeRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("PVSSDeal: %v", err)
	}
	buf, err := trs.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializePVSSTranscript(buf, f.suite, f.cfg)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if err := PVSSVerify(f.suite, f.cfg, got, f.dealer.PK, f.playerPKs); err != nil {
		t.Fatalf("PVSSVerify on deserialized: %v", err)
	}
	// Round-trip determinism: re-serializing yields identical bytes.
	buf2, err := got.Serialize()
	if err != nil {
		t.Fatalf("Serialize after deserialize: %v", err)
	}
	if len(buf) != len(buf2) {
		t.Fatalf("re-serialize length differs: %d vs %d", len(buf), len(buf2))
	}
	for i := range buf {
		if buf[i] != buf2[i] {
			t.Fatalf("re-serialize byte %d differs: %02x vs %02x", i, buf[i], buf2[i])
		}
	}
}

// TestPVSSDecryptRecoversShamirShare: every player's decrypted share must
// satisfy share_i · G == ExpectedShareCommitment(VSS, i), i.e. the player
// recovers exactly the Shamir evaluation f(i).
func TestPVSSDecryptRecoversShamirShare(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 4, 3)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("PVSSDeal: %v", err)
	}
	outer := f.suite.OuterGroup()
	for _, p := range f.players {
		share, err := PVSSDecryptShare(f.suite, f.cfg, trs, p.ID, p.SK, f.dealer.PK)
		if err != nil {
			t.Fatalf("decrypt player %d: %v", p.ID, err)
		}
		shareG := outer.NewPoint().ScalarMult(share, outer.Generator())
		expected, err := ExpectedShareCommitment(outer, trs.VSSCommitments, p.ID)
		if err != nil {
			t.Fatalf("expected[%d]: %v", p.ID, err)
		}
		if !shareG.Equal(expected) {
			t.Errorf("player %d decrypted share does not match VSS evaluation", p.ID)
		}
	}
}

// TestPVSSInvalidConfig covers the config-shape rejections surfaced by Deal.
func TestPVSSInvalidConfig(t *testing.T) {
	doWarmup(t)
	inner := &bjj.BJJ{}
	suite := NewBN254BJJSuite()
	players := makePlayers(t, inner, 3)
	dealer := makeDealer(t, inner, 3)
	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		cfg     *PVSSConfig
		wantErr error
	}{
		{"T<2", &PVSSConfig{N: 3, T: 1, SessionID: sid}, ErrPVSSInvalidConfig},
		{"N<T", &PVSSConfig{N: 2, T: 3, SessionID: sid}, ErrPVSSInvalidConfig},
		{"N>Max", &PVSSConfig{N: MaxParticipants + 1, T: 2, SessionID: sid}, ErrPVSSInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PVSSDeal(suite, tc.cfg, dealer, players, rand.Reader)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPVSSPlayerCountMismatch(t *testing.T) {
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	// Deal with only 2 players instead of 3.
	_, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players[:2], rand.Reader)
	if !errors.Is(err, ErrPVSSPlayerCount) {
		t.Fatalf("err=%v, want ErrPVSSPlayerCount", err)
	}
}

func TestPVSSDealerIsPlayer(t *testing.T) {
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	// Re-use player 1's keys as the dealer.
	rogue := &Participant{ID: f.cfg.N + 1, SK: f.players[0].SK, PK: f.players[0].PK}
	_, err := PVSSDeal(f.suite, f.cfg, rogue, f.players, rand.Reader)
	if !errors.Is(err, ErrPVSSDealerIsPlayer) {
		t.Fatalf("err=%v, want ErrPVSSDealerIsPlayer", err)
	}
}

func TestPVSSDealBadPlayerIDs(t *testing.T) {
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)

	t.Run("duplicate", func(t *testing.T) {
		bad := make([]*Participant, 3)
		copy(bad, f.players)
		bad[2] = &Participant{ID: bad[0].ID, SK: f.players[2].SK, PK: f.players[2].PK}
		_, err := PVSSDeal(f.suite, f.cfg, f.dealer, bad, rand.Reader)
		if !errors.Is(err, ErrDuplicateNodeID) {
			t.Fatalf("err=%v, want ErrDuplicateNodeID", err)
		}
	})
	t.Run("out-of-range", func(t *testing.T) {
		bad := make([]*Participant, 3)
		copy(bad, f.players)
		bad[2] = &Participant{ID: 99, SK: f.players[2].SK, PK: f.players[2].PK}
		_, err := PVSSDeal(f.suite, f.cfg, f.dealer, bad, rand.Reader)
		if !errors.Is(err, ErrInvalidNodeID) {
			t.Fatalf("err=%v, want ErrInvalidNodeID", err)
		}
	})
}

// TestPVSSVerifyTamper exercises rejection of transcripts that have been
// altered after a valid deal: wrong dealerPK, mutated R, mutated z, mutated
// VSS commitment, and mutated RandomMsg.
func TestPVSSVerifyTamper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("deal: %v", err)
	}

	// Wrong dealerPK: eVRF proofs bind to the right one, so this fails.
	bogusSK, _ := f.inner.RandomScalar(rand.Reader)
	bogusPK := f.inner.NewPoint().ScalarMult(bogusSK, f.inner.Generator())
	if err := PVSSVerify(f.suite, f.cfg, trs, bogusPK, f.playerPKs); err == nil {
		t.Error("expected failure with wrong dealerPK, got nil")
	}

	// Swap two playerPKs: fails eVRF for those positions.
	swapped := append([]group.Point(nil), f.playerPKs...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if err := PVSSVerify(f.suite, f.cfg, trs, f.dealer.PK, swapped); err == nil {
		t.Error("expected failure with swapped playerPKs, got nil")
	}

	// Mutate RandomMsg → alpha unchanged but H1/H2 change → eVRF fail.
	mutated := clonePVSS(t, trs)
	mutated.RandomMsg[0] ^= 0x01
	if err := PVSSVerify(f.suite, f.cfg, mutated, f.dealer.PK, f.playerPKs); err == nil {
		t.Error("expected failure with mutated RandomMsg, got nil")
	}

	// Mutate R for player 0: VSS alg check fails.
	mutated = clonePVSS(t, trs)
	outer := f.suite.OuterGroup()
	mutated.Ciphertexts[0].RCommitment = outer.NewPoint().Add(
		mutated.Ciphertexts[0].RCommitment, outer.Generator(),
	)
	if err := PVSSVerify(f.suite, f.cfg, mutated, f.dealer.PK, f.playerPKs); err == nil {
		t.Error("expected failure with mutated R, got nil")
	}

	// Mutate z for player 0: VSS alg check fails.
	mutated = clonePVSS(t, trs)
	oneBuf := make([]byte, 32)
	oneBuf[31] = 1
	one, err := outer.NewScalar().SetBytes(oneBuf)
	if err != nil {
		t.Fatal(err)
	}
	mutated.Ciphertexts[0].EncryptedShare = outer.NewScalar().Add(
		mutated.Ciphertexts[0].EncryptedShare, one,
	)
	if err := PVSSVerify(f.suite, f.cfg, mutated, f.dealer.PK, f.playerPKs); err == nil {
		t.Error("expected failure with mutated z, got nil")
	}

	// Mutate a VSS commitment: VSS alg check fails for every player.
	mutated = clonePVSS(t, trs)
	mutated.VSSCommitments[0] = outer.NewPoint().Add(
		mutated.VSSCommitments[0], outer.Generator(),
	)
	if err := PVSSVerify(f.suite, f.cfg, mutated, f.dealer.PK, f.playerPKs); err == nil {
		t.Error("expected failure with mutated VSS[0], got nil")
	}

	// Wrong SessionID: alpha and H1/H2 change → eVRF fail.
	var badSid SessionID
	if _, err := rand.Read(badSid[:]); err != nil {
		t.Fatal(err)
	}
	wrongCfg := &PVSSConfig{N: f.cfg.N, T: f.cfg.T, SessionID: badSid}
	if err := PVSSVerify(f.suite, wrongCfg, trs, f.dealer.PK, f.playerPKs); err == nil {
		t.Error("expected failure with wrong sessionID, got nil")
	}
}

func TestPVSSVerifyStructural(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("deal: %v", err)
	}

	// Truncated Ciphertexts list.
	short := clonePVSS(t, trs)
	short.Ciphertexts = short.Ciphertexts[:f.cfg.N-1]
	if err := PVSSVerify(f.suite, f.cfg, short, f.dealer.PK, f.playerPKs); !errors.Is(err, ErrPVSSTranscriptShape) {
		t.Errorf("truncated Ciphertexts err=%v, want ErrPVSSTranscriptShape", err)
	}

	// Truncated VSSCommitments length.
	short = clonePVSS(t, trs)
	short.VSSCommitments = short.VSSCommitments[:f.cfg.T-1]
	if err := PVSSVerify(f.suite, f.cfg, short, f.dealer.PK, f.playerPKs); !errors.Is(err, ErrInvalidVSSLength) {
		t.Errorf("truncated VSS err=%v, want ErrInvalidVSSLength", err)
	}

	// Wrong playerPKs length.
	if err := PVSSVerify(f.suite, f.cfg, trs, f.dealer.PK, f.playerPKs[:2]); !errors.Is(err, ErrPVSSPlayerCount) {
		t.Errorf("short playerPKs err=%v, want ErrPVSSPlayerCount", err)
	}

	// Identity dealer PK.
	identity := f.suite.OuterGroup().NewPoint() // wrong group, but any identity suffices
	_ = identity
	innerIdentity := f.inner.NewPoint()
	if err := PVSSVerify(f.suite, f.cfg, trs, innerIdentity, f.playerPKs); !errors.Is(err, ErrIdentityPoint) {
		t.Errorf("identity dealerPK err=%v, want ErrIdentityPoint", err)
	}
}

func TestPVSSDeserializeRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	doWarmup(t)
	f := newPVSSFixture(t, 3, 2)
	trs, err := PVSSDeal(f.suite, f.cfg, f.dealer, f.players, rand.Reader)
	if err != nil {
		t.Fatalf("deal: %v", err)
	}
	buf, err := trs.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	t.Run("truncated", func(t *testing.T) {
		if _, err := DeserializePVSSTranscript(buf[:len(buf)-1], f.suite, f.cfg); err == nil {
			t.Error("expected error on truncated buffer")
		}
	})
	t.Run("trailing-bytes", func(t *testing.T) {
		extended := append(append([]byte(nil), buf...), 0x00)
		if _, err := DeserializePVSSTranscript(extended, f.suite, f.cfg); err == nil {
			t.Error("expected error on trailing bytes")
		}
	})
	t.Run("wrong-config-N", func(t *testing.T) {
		badCfg := &PVSSConfig{N: f.cfg.N + 1, T: f.cfg.T, SessionID: f.cfg.SessionID}
		if _, err := DeserializePVSSTranscript(buf, f.suite, badCfg); err == nil {
			t.Error("expected error when deserializing with wrong N")
		}
	})
	t.Run("wrong-config-T", func(t *testing.T) {
		badCfg := &PVSSConfig{N: f.cfg.N, T: f.cfg.T + 1, SessionID: f.cfg.SessionID}
		if _, err := DeserializePVSSTranscript(buf, f.suite, badCfg); err == nil {
			t.Error("expected error when deserializing with wrong T")
		}
	})
	t.Run("invalid-point", func(t *testing.T) {
		// Overwrite the first byte of the first VSS commitment with an
		// invalid prefix that cannot decompress to a curve point.
		corrupted := append([]byte(nil), buf...)
		// RandomMsg is the first 32 bytes; VSS[0] starts at offset 32.
		corrupted[32] = 0xff
		if _, err := DeserializePVSSTranscript(corrupted, f.suite, f.cfg); err == nil {
			t.Error("expected error on invalid point bytes")
		}
	})
}

// clonePVSS roundtrips a transcript through serialize/deserialize to produce
// an independent, mutable copy. Used by the tamper tests so mutations on one
// copy do not leak into the original.
func clonePVSS(t *testing.T, trs *PVSSTranscript) *PVSSTranscript {
	t.Helper()
	suite := NewBN254BJJSuite()
	buf, err := trs.Serialize()
	if err != nil {
		t.Fatalf("clonePVSS Serialize: %v", err)
	}
	cfg := &PVSSConfig{N: len(trs.Ciphertexts), T: len(trs.VSSCommitments)}
	got, err := DeserializePVSSTranscript(buf, suite, cfg)
	if err != nil {
		t.Fatalf("clonePVSS Deserialize: %v", err)
	}
	return got
}
