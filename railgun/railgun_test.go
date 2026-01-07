package railgun

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/f3rmion/fy/bjj"
	"github.com/f3rmion/fy/frost"
)

func TestNewThresholdWallet(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		total     int
		wantErr   bool
	}{
		{"2-of-3", 2, 3, false},
		{"3-of-5", 3, 5, false},
		{"2-of-2", 2, 2, false},
		{"threshold too low", 1, 3, true},
		{"total less than threshold", 3, 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw, err := NewThresholdWallet(tt.threshold, tt.total)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewThresholdWallet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tw == nil {
				t.Error("NewThresholdWallet() returned nil without error")
			}
		})
	}
}

func TestGenerateShares(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("GenerateShares() returned %d shares, want 3", len(shares))
	}

	// Verify all shares have the same group key
	var groupKey *big.Int
	for i, share := range shares {
		x, y := share.SpendingPublicKey()
		if x == nil || y == nil {
			t.Errorf("Share %d has nil public key coordinates", i)
			continue
		}

		// Encode as single value for comparison
		key := new(big.Int).Add(x, y)
		if groupKey == nil {
			groupKey = key
		} else if groupKey.Cmp(key) != 0 {
			t.Errorf("Share %d has different group key", i)
		}
	}
}

func TestThresholdSigning(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test transaction sighash")

	// Sign with threshold (2) participants
	sig, err := tw.Sign(shares[:2], message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature components are non-nil
	rx, ry, s := sig.Components()
	if rx == nil || ry == nil || s == nil {
		t.Error("Signature has nil components")
	}

	// Verify signature bytes format
	sigBytes := sig.Bytes()
	if len(sigBytes) != 96 {
		t.Errorf("Signature bytes length = %d, want 96", len(sigBytes))
	}

	// Verify the signature
	groupKey := shares[0].SpendingKeyShare.GroupKey
	if !tw.Verify(groupKey, message, sig) {
		t.Error("Signature verification failed")
	}
}

func TestSigningWithDifferentSubsets(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test message")
	groupKey := shares[0].SpendingKeyShare.GroupKey

	// Test signing with different pairs
	subsets := [][]*Share{
		{shares[0], shares[1]}, // 1,2
		{shares[0], shares[2]}, // 1,3
		{shares[1], shares[2]}, // 2,3
	}

	for i, subset := range subsets {
		sig, err := tw.Sign(subset, message)
		if err != nil {
			t.Errorf("Subset %d: Sign() error = %v", i, err)
			continue
		}

		if !tw.Verify(groupKey, message, sig) {
			t.Errorf("Subset %d: Signature verification failed", i)
		}
	}
}

func TestInsufficientSigners(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test message")

	// Try to sign with only 1 signer (below threshold of 2)
	_, err = tw.Sign(shares[:1], message)
	if err == nil {
		t.Error("Sign() should fail with insufficient signers")
	}
}

func TestSigningSessionRounds(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test transaction")

	// Create signing session
	session, err := tw.NewSigningSession(shares[:2], message)
	if err != nil {
		t.Fatalf("NewSigningSession() error = %v", err)
	}

	// Round 1
	commitments, err := session.Round1(rand.Reader)
	if err != nil {
		t.Fatalf("Round1() error = %v", err)
	}
	if len(commitments) != 2 {
		t.Errorf("Round1() returned %d commitments, want 2", len(commitments))
	}

	// Round 2
	sig, err := session.Round2()
	if err != nil {
		t.Fatalf("Round2() error = %v", err)
	}

	// Verify
	groupKey := shares[0].SpendingKeyShare.GroupKey
	if !tw.Verify(groupKey, message, sig) {
		t.Error("Signature verification failed")
	}
}

func TestDeriveViewingKey(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	groupKey := shares[0].SpendingKeyShare.GroupKey

	// Derive viewing key
	vk, err := DeriveViewingKey(groupKey)
	if err != nil {
		t.Fatalf("DeriveViewingKey() error = %v", err)
	}

	if len(vk) != 32 {
		t.Errorf("DeriveViewingKey() length = %d, want 32", len(vk))
	}

	// Verify all shares derive the same viewing key
	for i, share := range shares {
		vk2, err := DeriveViewingKey(share.SpendingKeyShare.GroupKey)
		if err != nil {
			t.Errorf("Share %d: DeriveViewingKey() error = %v", i, err)
			continue
		}

		if string(vk) != string(vk2) {
			t.Errorf("Share %d: derived different viewing key", i)
		}
	}
}

func TestDeriveMasterPublicKey(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	groupKey := shares[0].SpendingKeyShare.GroupKey

	vk, err := DeriveViewingKey(groupKey)
	if err != nil {
		t.Fatalf("DeriveViewingKey() error = %v", err)
	}

	mpk, err := DeriveMasterPublicKey(groupKey, vk)
	if err != nil {
		t.Fatalf("DeriveMasterPublicKey() error = %v", err)
	}

	if mpk == nil || mpk.Sign() == 0 {
		t.Error("DeriveMasterPublicKey() returned zero or nil")
	}
}

func TestComputeNullifier(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	groupKey := shares[0].SpendingKeyShare.GroupKey

	vk, err := DeriveViewingKey(groupKey)
	if err != nil {
		t.Fatalf("DeriveViewingKey() error = %v", err)
	}

	// Compute nullifiers for different leaf indices
	leafIndices := []uint64{0, 1, 100, 1000000}
	nullifiers := make([]*big.Int, len(leafIndices))

	for i, idx := range leafIndices {
		nullifier, err := ComputeNullifier(vk, idx)
		if err != nil {
			t.Errorf("ComputeNullifier(%d) error = %v", idx, err)
			continue
		}
		nullifiers[i] = nullifier
	}

	// Verify nullifiers are unique
	for i := 0; i < len(nullifiers); i++ {
		for j := i + 1; j < len(nullifiers); j++ {
			if nullifiers[i] != nil && nullifiers[j] != nil {
				if nullifiers[i].Cmp(nullifiers[j]) == 0 {
					t.Errorf("Nullifiers %d and %d are equal", i, j)
				}
			}
		}
	}

	// Verify same input produces same nullifier
	null1, _ := ComputeNullifier(vk, 42)
	null2, _ := ComputeNullifier(vk, 42)
	if null1.Cmp(null2) != 0 {
		t.Error("Same input produced different nullifiers")
	}
}

func TestFromFROSTSignature(t *testing.T) {
	// Create a FROST signature directly for testing conversion
	g := &bjj.BJJ{}
	f, err := frost.NewWithHasher(g, 2, 3, frost.NewPoseidonHasher())
	if err != nil {
		t.Fatalf("NewWithHasher() error = %v", err)
	}

	// Generate key shares using DKG
	participants := make([]*frost.Participant, 3)
	for i := 0; i < 3; i++ {
		p, err := f.NewParticipant(rand.Reader, i+1)
		if err != nil {
			t.Fatalf("NewParticipant() error = %v", err)
		}
		participants[i] = p
	}

	broadcasts := make([]*frost.Round1Data, 3)
	for i, p := range participants {
		broadcasts[i] = p.Round1Broadcast()
	}

	// Exchange private shares
	for i, sender := range participants {
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			privateData := f.Round1PrivateSend(sender, j+1)
			err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
			if err != nil {
				t.Fatalf("Round2ReceiveShare() error = %v", err)
			}
		}
	}

	keyShares := make([]*frost.KeyShare, 3)
	for i, p := range participants {
		ks, err := f.Finalize(p, broadcasts)
		if err != nil {
			t.Fatalf("Finalize() error = %v", err)
		}
		keyShares[i] = ks
	}

	// Sign
	message := []byte("test message")
	nonces := make([]*frost.SigningNonce, 2)
	commitments := make([]*frost.SigningCommitment, 2)

	for i := 0; i < 2; i++ {
		nonce, commitment, err := f.SignRound1(rand.Reader, keyShares[i])
		if err != nil {
			t.Fatalf("SignRound1() error = %v", err)
		}
		nonces[i] = nonce
		commitments[i] = commitment
	}

	sigShares := make([]*frost.SignatureShare, 2)
	for i := 0; i < 2; i++ {
		share, err := f.SignRound2(keyShares[i], nonces[i], message, commitments)
		if err != nil {
			t.Fatalf("SignRound2() error = %v", err)
		}
		sigShares[i] = share
	}

	frostSig, err := f.Aggregate(message, commitments, sigShares)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	// Convert to Railgun format
	railgunSig, err := FromFROSTSignature(frostSig)
	if err != nil {
		t.Fatalf("FromFROSTSignature() error = %v", err)
	}

	// Verify components
	rx, ry, s := railgunSig.Components()
	if rx == nil || ry == nil || s == nil {
		t.Error("Converted signature has nil components")
	}

	// Verify bytes format
	sigBytes := railgunSig.Bytes()
	if len(sigBytes) != 96 {
		t.Errorf("Signature bytes length = %d, want 96", len(sigBytes))
	}
}

func TestSignatureBytes(t *testing.T) {
	sig := &Signature{
		RX: big.NewInt(12345),
		RY: big.NewInt(67890),
		S:  big.NewInt(11111),
	}

	bytes := sig.Bytes()
	if len(bytes) != 96 {
		t.Errorf("Bytes() length = %d, want 96", len(bytes))
	}

	// Verify the bytes can be parsed back
	rxParsed := new(big.Int).SetBytes(bytes[0:32])
	ryParsed := new(big.Int).SetBytes(bytes[32:64])
	sParsed := new(big.Int).SetBytes(bytes[64:96])

	if sig.RX.Cmp(rxParsed) != 0 {
		t.Error("RX mismatch after round-trip")
	}
	if sig.RY.Cmp(ryParsed) != 0 {
		t.Error("RY mismatch after round-trip")
	}
	if sig.S.Cmp(sParsed) != 0 {
		t.Error("S mismatch after round-trip")
	}
}

func TestWrongMessageVerification(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("correct message")
	sig, err := tw.Sign(shares[:2], message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	groupKey := shares[0].SpendingKeyShare.GroupKey

	// Verify with correct message - should pass
	if !tw.Verify(groupKey, message, sig) {
		t.Error("Verification failed with correct message")
	}

	// Verify with wrong message - should fail
	wrongMessage := []byte("wrong message")
	if tw.Verify(groupKey, wrongMessage, sig) {
		t.Error("Verification should fail with wrong message")
	}
}

func TestShieldSign(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	// Verify all shares have the same shield public key
	shieldPubKey := shares[0].ShieldPublicKey()
	for i := 1; i < len(shares); i++ {
		if string(shares[i].ShieldPublicKey()) != string(shieldPubKey) {
			t.Errorf("Share %d has different shield public key", i)
		}
	}

	// Sign with shield (secp256k1) for shield operations
	message := []byte("RAILGUN_SHIELD") // This would be keccak256("RAILGUN_SHIELD") in practice

	sig, err := tw.ShieldSign(shares[:2], message)
	if err != nil {
		t.Fatalf("ShieldSign() error = %v", err)
	}

	// Verify signature components are non-nil
	if sig.R == nil || sig.Z == nil {
		t.Error("ShieldSignature has nil components")
	}

	// Verify the signature
	shieldGroupKey := shares[0].ShieldKeyShare.GroupKey
	if !tw.VerifyShield(shieldGroupKey, message, sig) {
		t.Error("Shield signature verification failed")
	}

	// Verify wrong message fails
	if tw.VerifyShield(shieldGroupKey, []byte("wrong message"), sig) {
		t.Error("Shield signature should not verify with wrong message")
	}
}

func TestShieldSignWithDifferentSubsets(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test shield message")
	shieldGroupKey := shares[0].ShieldKeyShare.GroupKey

	// Test signing with different pairs
	subsets := [][]*Share{
		{shares[0], shares[1]}, // 1,2
		{shares[0], shares[2]}, // 1,3
		{shares[1], shares[2]}, // 2,3
	}

	for i, subset := range subsets {
		sig, err := tw.ShieldSign(subset, message)
		if err != nil {
			t.Errorf("Subset %d: ShieldSign() error = %v", i, err)
			continue
		}

		if !tw.VerifyShield(shieldGroupKey, message, sig) {
			t.Errorf("Subset %d: Shield signature verification failed", i)
		}
	}
}

func TestCombinedDKGProducesDifferentKeys(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	// Shield (secp256k1) and spending (BJJ) keys should be different
	shieldKey := shares[0].ShieldPublicKey()
	spendingX, spendingY := shares[0].SpendingPublicKey()

	// Convert spending key to bytes for comparison
	spendingKeyBytes := append(spendingX.Bytes(), spendingY.Bytes()...)

	if string(shieldKey) == string(spendingKeyBytes) {
		t.Error("Shield and spending keys should be different (different curves)")
	}

	// Both should be non-zero
	if len(shieldKey) == 0 {
		t.Error("Shield key should not be empty")
	}
	if spendingX.Sign() == 0 && spendingY.Sign() == 0 {
		t.Error("Spending key should not be zero")
	}
}

func TestShieldPublicKeyFormats(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	// Test compressed format
	compressed := shares[0].ShieldPublicKey()
	if len(compressed) != 33 {
		t.Errorf("Compressed shield public key should be 33 bytes, got %d", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Errorf("Compressed key should start with 0x02 or 0x03, got 0x%02x", compressed[0])
	}

	// Test uncompressed format
	uncompressed := shares[0].ShieldPublicKeyUncompressed()
	if len(uncompressed) != 65 {
		t.Errorf("Uncompressed shield public key should be 65 bytes, got %d", len(uncompressed))
	}
	if uncompressed[0] != 0x04 {
		t.Errorf("Uncompressed key should start with 0x04, got 0x%02x", uncompressed[0])
	}
}

func TestShieldSignatureToEthereum(t *testing.T) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		t.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("test message")
	sig, err := tw.ShieldSign(shares[:2], message)
	if err != nil {
		t.Fatalf("ShieldSign() error = %v", err)
	}

	r, s := sig.ToEthereumSignature()
	if r == nil || s == nil {
		t.Error("ToEthereumSignature() returned nil")
	}

	if len(r) != 32 {
		t.Errorf("r should be 32 bytes, got %d", len(r))
	}
	if len(s) != 32 {
		t.Errorf("s should be 32 bytes, got %d", len(s))
	}
}

func BenchmarkThresholdSign(b *testing.B) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		b.Fatalf("NewThresholdWallet() error = %v", err)
	}

	shares, err := tw.GenerateShares(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateShares() error = %v", err)
	}

	message := []byte("benchmark transaction sighash")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tw.Sign(shares[:2], message)
		if err != nil {
			b.Fatalf("Sign() error = %v", err)
		}
	}
}

func BenchmarkDKG(b *testing.B) {
	tw, err := NewThresholdWallet(2, 3)
	if err != nil {
		b.Fatalf("NewThresholdWallet() error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tw.GenerateShares(rand.Reader)
		if err != nil {
			b.Fatalf("GenerateShares() error = %v", err)
		}
	}
}
