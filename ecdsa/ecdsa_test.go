package ecdsa

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Test Fixtures - Cached Key Shares
// =============================================================================

const testFixtureDir = "testdata"

// fixtureMu protects fixture creation to avoid race conditions in parallel tests.
var fixtureMu sync.Mutex

// fixtureKey creates a unique key for caching based on threshold and parties.
func fixtureKey(threshold, totalParties int) string {
	return fmt.Sprintf("keyshares_%d_of_%d.json", threshold, totalParties)
}

// loadFixture attempts to load cached key shares from disk.
func loadFixture(t *testing.T, threshold, totalParties int) ([]*ECDSAKeyShare, bool) {
	t.Helper()

	fixturePath := filepath.Join(testFixtureDir, fixtureKey(threshold, totalParties))
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return nil, false
	}

	var keyShares []*ECDSAKeyShare
	if err := json.Unmarshal(data, &keyShares); err != nil {
		t.Logf("Failed to unmarshal fixture (will regenerate): %v", err)
		return nil, false
	}

	// Validate the key shares
	if len(keyShares) != totalParties {
		t.Logf("Fixture has wrong number of key shares (expected %d, got %d), will regenerate", totalParties, len(keyShares))
		return nil, false
	}

	for i, ks := range keyShares {
		if ks == nil || ks.SaveData == nil {
			t.Logf("Fixture key share %d is invalid, will regenerate", i+1)
			return nil, false
		}
		// Note: ks.Threshold is stored in tss-lib format (t where t+1 signers needed),
		// so we compare against threshold-1
		tssThreshold := threshold - 1
		if ks.Threshold != tssThreshold || ks.TotalParties != totalParties {
			t.Logf("Fixture key share %d has wrong parameters (threshold=%d, want=%d, parties=%d, want=%d), will regenerate",
				i+1, ks.Threshold, tssThreshold, ks.TotalParties, totalParties)
			return nil, false
		}
	}

	t.Logf("Loaded cached key shares from %s", fixturePath)
	return keyShares, true
}

// saveFixture saves key shares to disk for future test runs.
func saveFixture(t *testing.T, threshold, totalParties int, keyShares []*ECDSAKeyShare) {
	t.Helper()

	// Ensure testdata directory exists
	if err := os.MkdirAll(testFixtureDir, 0755); err != nil {
		t.Logf("Failed to create testdata directory: %v", err)
		return
	}

	data, err := json.MarshalIndent(keyShares, "", "  ")
	if err != nil {
		t.Logf("Failed to marshal key shares: %v", err)
		return
	}

	fixturePath := filepath.Join(testFixtureDir, fixtureKey(threshold, totalParties))
	if err := os.WriteFile(fixturePath, data, 0600); err != nil {
		t.Logf("Failed to save fixture: %v", err)
		return
	}

	t.Logf("Saved key shares to %s for future test runs", fixturePath)
}

// getOrCreateKeyShares returns cached key shares or generates new ones.
// Thread-safe for parallel tests.
func getOrCreateKeyShares(t *testing.T, threshold, totalParties int) []*ECDSAKeyShare {
	t.Helper()

	// Lock to prevent multiple tests from creating the same fixture simultaneously
	fixtureMu.Lock()
	defer fixtureMu.Unlock()

	// Try to load from cache first
	if keyShares, ok := loadFixture(t, threshold, totalParties); ok {
		return keyShares
	}

	// Generate new key shares
	t.Log("No cached key shares found, running DKG (this will be cached for future runs)...")
	keyShares := runDKG(t, threshold, totalParties)

	// Save for future runs
	saveFixture(t, threshold, totalParties, keyShares)

	return keyShares
}

// TestECDSADKG_2of3 tests DKG with 2-of-3 threshold.
func TestECDSADKG_2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DKG test in short mode (Paillier key generation is slow)")
	}

	threshold := 2
	totalParties := 3

	keyShares := runDKG(t, threshold, totalParties)

	// Verify all key shares have the same group public key
	var pubKeyBytes []byte
	for i, ks := range keyShares {
		pkBytes, err := GetPublicKeyBytes(ks)
		if err != nil {
			t.Fatalf("party %d: failed to get public key: %v", i+1, err)
		}

		if pubKeyBytes == nil {
			pubKeyBytes = pkBytes
		} else if !bytes.Equal(pubKeyBytes, pkBytes) {
			t.Fatalf("party %d: public key mismatch", i+1)
		}

		// Verify Ethereum address derivation
		addr, err := KeyShareToEthAddress(ks)
		if err != nil {
			t.Fatalf("party %d: failed to derive eth address: %v", i+1, err)
		}
		t.Logf("Party %d Ethereum address: %s", i+1, addr.Hex())
	}

	t.Logf("DKG successful! Group public key: %x", pubKeyBytes)
}

// TestECDSADKG_3of5 tests DKG with 3-of-5 threshold.
func TestECDSADKG_3of5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DKG test in short mode (Paillier key generation is slow)")
	}

	threshold := 3
	totalParties := 5

	keyShares := runDKG(t, threshold, totalParties)

	// Verify
	var pubKeyBytes []byte
	for i, ks := range keyShares {
		pkBytes, err := GetPublicKeyBytes(ks)
		if err != nil {
			t.Fatalf("party %d: failed to get public key: %v", i+1, err)
		}

		if pubKeyBytes == nil {
			pubKeyBytes = pkBytes
		} else if !bytes.Equal(pubKeyBytes, pkBytes) {
			t.Fatalf("party %d: public key mismatch", i+1)
		}
	}

	t.Logf("3-of-5 DKG successful!")
}

// TestECDSASigning_2of3 tests signing with 2-of-3 threshold.
func TestECDSASigning_2of3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signing test in short mode")
	}
	t.Parallel()

	threshold := 2
	totalParties := 3
	keyShares := getOrCreateKeyShares(t, threshold, totalParties)

	// Create a message to sign
	message := make([]byte, 32)
	if _, err := rand.Read(message); err != nil {
		t.Fatal(err)
	}

	// Sign with parties 1 and 2 (threshold = 2)
	signerKeyShares := keyShares[:2]
	signature := runSigning(t, signerKeyShares, message)

	// Verify signature
	pubKey, err := GetPublicKey(keyShares[0])
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	if !VerifySignature(pubKey, message, signature) {
		t.Fatal("signature verification failed")
	}

	t.Logf("Signing successful! R=%s, S=%s, V=%d", signature.R.String(), signature.S.String(), signature.V)
}

// TestECDSASignatureEthereumCompatible tests that signatures are Ethereum compatible.
func TestECDSASignatureEthereumCompatible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Ethereum compatibility test in short mode")
	}
	t.Parallel()

	threshold := 2
	totalParties := 3
	keyShares := getOrCreateKeyShares(t, threshold, totalParties)

	// Get expected address
	expectedAddr, err := KeyShareToEthAddress(keyShares[0])
	if err != nil {
		t.Fatal(err)
	}

	// Create a message to sign
	message := make([]byte, 32)
	if _, err := rand.Read(message); err != nil {
		t.Fatal(err)
	}

	// Sign
	signerKeyShares := keyShares[:2]
	signature := runSigning(t, signerKeyShares, message)

	// Normalize for Ethereum
	signature = NormalizeSForEthereum(signature)

	// Recover public key
	recoveredPubKey, err := RecoverPublicKey(message, signature)
	if err != nil {
		t.Fatalf("failed to recover public key: %v", err)
	}

	// Derive address from recovered key
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)

	if recoveredAddr != expectedAddr {
		t.Fatalf("address mismatch: expected %s, got %s", expectedAddr.Hex(), recoveredAddr.Hex())
	}

	t.Logf("Ethereum compatible! Address: %s", recoveredAddr.Hex())
}

// TestECDSAKeyShareSerialization tests key share serialization/deserialization.
func TestECDSAKeyShareSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping serialization test in short mode")
	}
	t.Parallel()

	threshold := 2
	totalParties := 3
	keyShares := getOrCreateKeyShares(t, threshold, totalParties)

	for i, ks := range keyShares {
		// Serialize
		data, err := SerializeKeyShare(ks)
		if err != nil {
			t.Fatalf("party %d: failed to serialize: %v", i+1, err)
		}

		// Deserialize
		restored, err := DeserializeKeyShare(data)
		if err != nil {
			t.Fatalf("party %d: failed to deserialize: %v", i+1, err)
		}

		// Verify
		if restored.PartyID != ks.PartyID {
			t.Fatalf("party %d: party ID mismatch", i+1)
		}
		if restored.Threshold != ks.Threshold {
			t.Fatalf("party %d: threshold mismatch", i+1)
		}
		if restored.TotalParties != ks.TotalParties {
			t.Fatalf("party %d: total parties mismatch", i+1)
		}

		// Verify public key matches
		origPK, _ := GetPublicKeyBytes(ks)
		restoredPK, _ := GetPublicKeyBytes(restored)
		if !bytes.Equal(origPK, restoredPK) {
			t.Fatalf("party %d: public key mismatch after restoration", i+1)
		}
	}

	t.Log("Serialization/deserialization successful!")
}

// runDKG runs the DKG protocol and returns key shares.
func runDKG(t *testing.T, threshold, totalParties int) []*ECDSAKeyShare {
	t.Helper()

	// Create participants
	participants := make([]*DKGParticipant, totalParties)
	for i := 0; i < totalParties; i++ {
		p, err := NewDKGParticipant(i+1, threshold, totalParties)
		if err != nil {
			t.Fatalf("failed to create participant %d: %v", i+1, err)
		}
		participants[i] = p
	}

	// Generate pre-params in parallel (this is the slow part)
	t.Log("Generating Paillier keys (this may take a while)...")
	var wg sync.WaitGroup
	for i, p := range participants {
		wg.Add(1)
		go func(idx int, participant *DKGParticipant) {
			defer wg.Done()
			if err := participant.GeneratePreParams(5 * time.Minute); err != nil {
				t.Errorf("participant %d: failed to generate pre-params: %v", idx+1, err)
			}
		}(i, p)
	}
	wg.Wait()

	// === Round 1 ===
	t.Log("Round 1: Broadcasting commitments...")
	round1Data := make([]*DKGRound1Message, totalParties)
	for i, p := range participants {
		r1, err := p.Start()
		if err != nil {
			t.Fatalf("participant %d: round 1 failed: %v", i+1, err)
		}
		if len(r1) > 0 {
			round1Data[i] = r1[0]
		}
	}

	// === Round 2 ===
	t.Log("Round 2: Distributing shares...")
	allP2P := make([][]*DKGRound2Message1, totalParties)
	allBC := make([][]*DKGRound2Message2, totalParties)

	for i, p := range participants {
		p2p, bc, err := p.ProcessRound1(round1Data)
		if err != nil {
			t.Fatalf("participant %d: process round 1 failed: %v", i+1, err)
		}
		allP2P[i] = p2p
		allBC[i] = bc
	}

	// Collect P2P messages for each participant
	p2pForParty := make([][]*DKGRound2Message1, totalParties)
	for i := range participants {
		p2pForParty[i] = make([]*DKGRound2Message1, 0)
	}

	for _, p2pMsgs := range allP2P {
		for _, msg := range p2pMsgs {
			toID, _ := IntFromPartyID(msg.ToPartyID)
			if toID >= 1 && toID <= totalParties {
				p2pForParty[toID-1] = append(p2pForParty[toID-1], msg)
			}
		}
	}

	// Flatten broadcast messages
	allBCFlat := make([]*DKGRound2Message2, 0)
	for _, bcs := range allBC {
		allBCFlat = append(allBCFlat, bcs...)
	}

	// === Round 3 ===
	t.Log("Round 3: Decommitments...")
	round3Data := make([]*DKGRound3Message, totalParties)

	for i, p := range participants {
		r3, err := p.ProcessRound2(p2pForParty[i], allBCFlat)
		if err != nil {
			t.Fatalf("participant %d: process round 2 failed: %v", i+1, err)
		}
		if len(r3) > 0 {
			round3Data[i] = r3[0]
		}
	}

	// === Finalize ===
	t.Log("Finalizing DKG...")
	keyShares := make([]*ECDSAKeyShare, totalParties)

	for i, p := range participants {
		ks, err := p.ProcessRound3(round3Data)
		if err != nil {
			t.Fatalf("participant %d: finalize failed: %v", i+1, err)
		}
		keyShares[i] = ks
	}

	return keyShares
}

// runSigning runs the signing protocol and returns the signature.
func runSigning(t *testing.T, keyShares []*ECDSAKeyShare, message []byte) *ECDSASignature {
	t.Helper()

	numSigners := len(keyShares)

	// Create signer party IDs
	signerIDs := make([]string, numSigners)
	for i, ks := range keyShares {
		signerIDs[i] = ks.PartyID
	}

	// Create signing sessions
	sessions := make([]*SigningSession, numSigners)
	for i, ks := range keyShares {
		s, err := NewSigningSession(signerIDs, ks, message)
		if err != nil {
			t.Fatalf("failed to create signing session %d: %v", i+1, err)
		}
		sessions[i] = s
	}

	// === Round 1 ===
	round1Msgs := make([][]*SigningRoundMessage, numSigners)
	for i, s := range sessions {
		msgs, err := s.Start()
		if err != nil {
			t.Fatalf("signer %d: round 1 failed: %v", i+1, err)
		}
		round1Msgs[i] = msgs
	}

	// === Process Rounds ===
	// GG20 signing has 9 rounds, but we need one more iteration to process the final messages
	maxRounds := 15
	allMsgs := flattenMessages(round1Msgs)

	for round := 2; round <= maxRounds; round++ {
		if len(allMsgs) == 0 {
			break
		}

		allComplete := true
		nextRoundMsgs := make([][]*SigningRoundMessage, numSigners)

		for i, s := range sessions {
			if s.IsComplete() {
				continue
			}
			allComplete = false

			msgs, err := s.ProcessRound(allMsgs)
			if err != nil {
				t.Fatalf("signer %d: round %d failed: %v", i+1, round, err)
			}
			nextRoundMsgs[i] = msgs
		}

		if allComplete {
			break
		}

		allMsgs = flattenMessages(nextRoundMsgs)
	}

	// Wait for completion and get signature from first signer
	for i, s := range sessions {
		if s.IsComplete() {
			sig, err := s.GetSignature()
			if err != nil {
				t.Fatalf("failed to get signature: %v", err)
			}
			return sig
		}
		// Wait for completion if not already complete
		if err := s.WaitForCompletion(30 * time.Second); err != nil {
			t.Logf("signer %d: wait for completion: %v", i+1, err)
			continue
		}
		sig, err := s.GetSignature()
		if err != nil {
			t.Fatalf("failed to get signature: %v", err)
		}
		return sig
	}

	t.Fatal("signing did not complete")
	return nil
}

func flattenMessages(msgs [][]*SigningRoundMessage) []*SigningRoundMessage {
	var result []*SigningRoundMessage
	for _, m := range msgs {
		result = append(result, m...)
	}
	return result
}
