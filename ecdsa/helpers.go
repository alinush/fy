package ecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// KeyShareToEthAddress derives the Ethereum address from a key share.
func KeyShareToEthAddress(keyShare *ECDSAKeyShare) (common.Address, error) {
	if keyShare.SaveData == nil {
		return common.Address{}, fmt.Errorf("no save data")
	}

	// The public key is in SaveData.ECDSAPub
	pubKey := keyShare.SaveData.ECDSAPub
	if pubKey == nil {
		return common.Address{}, fmt.Errorf("no public key in save data")
	}

	// Convert to go-ethereum ecdsa.PublicKey
	ethPubKey := ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     pubKey.X(),
		Y:     pubKey.Y(),
	}

	return crypto.PubkeyToAddress(ethPubKey), nil
}

// SerializeKeyShare serializes a key share for storage.
func SerializeKeyShare(keyShare *ECDSAKeyShare) ([]byte, error) {
	return json.Marshal(keyShare)
}

// DeserializeKeyShare deserializes a key share from storage.
func DeserializeKeyShare(data []byte) (*ECDSAKeyShare, error) {
	var keyShare ECDSAKeyShare
	if err := json.Unmarshal(data, &keyShare); err != nil {
		return nil, err
	}
	return &keyShare, nil
}

// SignatureToEthBytes converts signature to Ethereum format (65 bytes: r || s || v).
func SignatureToEthBytes(sig *ECDSASignature) []byte {
	result := make([]byte, 65)

	// Pad r to 32 bytes
	rBytes := sig.R.Bytes()
	copy(result[32-len(rBytes):32], rBytes)

	// Pad s to 32 bytes
	sBytes := sig.S.Bytes()
	copy(result[64-len(sBytes):64], sBytes)

	// V (recovery ID)
	result[64] = sig.V

	return result
}

// EthBytesToSignature converts Ethereum format bytes to signature.
func EthBytesToSignature(data []byte) (*ECDSASignature, error) {
	if len(data) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes, got %d", len(data))
	}

	r := new(big.Int).SetBytes(data[0:32])
	s := new(big.Int).SetBytes(data[32:64])
	v := data[64]

	return &ECDSASignature{
		R: r,
		S: s,
		V: v,
	}, nil
}

// NormalizeSForEthereum ensures s is in the lower half of the curve order.
// This is required by Ethereum's ecrecover (EIP-2).
func NormalizeSForEthereum(sig *ECDSASignature) *ECDSASignature {
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	if sig.S.Cmp(halfOrder) > 0 {
		// s = n - s
		newS := new(big.Int).Sub(curveOrder, sig.S)
		// Flip v
		newV := sig.V
		if newV == 27 {
			newV = 28
		} else {
			newV = 27
		}
		return &ECDSASignature{
			R: new(big.Int).Set(sig.R),
			S: newS,
			V: newV,
		}
	}
	return sig
}

// VerifySignature verifies an ECDSA signature against a public key.
func VerifySignature(pubKey *ecdsa.PublicKey, hash []byte, sig *ECDSASignature) bool {
	return ecdsa.Verify(pubKey, hash, sig.R, sig.S)
}

// RecoverPublicKey recovers the public key from a signature and message hash.
func RecoverPublicKey(hash []byte, sig *ECDSASignature) (*ecdsa.PublicKey, error) {
	sigBytes := SignatureToEthBytes(sig)

	// Adjust v for go-ethereum (expects 0 or 1, not 27 or 28)
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	pubKeyBytes, err := crypto.Ecrecover(hash, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("ecrecover: %w", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal pubkey: %w", err)
	}

	return pubKey, nil
}

// GetPublicKey returns the group public key from a key share.
func GetPublicKey(keyShare *ECDSAKeyShare) (*ecdsa.PublicKey, error) {
	if keyShare.SaveData == nil || keyShare.SaveData.ECDSAPub == nil {
		return nil, fmt.Errorf("no public key in key share")
	}

	return &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     keyShare.SaveData.ECDSAPub.X(),
		Y:     keyShare.SaveData.ECDSAPub.Y(),
	}, nil
}

// GetPublicKeyBytes returns the uncompressed public key bytes (65 bytes).
func GetPublicKeyBytes(keyShare *ECDSAKeyShare) ([]byte, error) {
	pubKey, err := GetPublicKey(keyShare)
	if err != nil {
		return nil, err
	}
	return crypto.FromECDSAPub(pubKey), nil
}

// GetPublicKeyCompressed returns the compressed public key bytes (33 bytes).
func GetPublicKeyCompressed(keyShare *ECDSAKeyShare) ([]byte, error) {
	pubKey, err := GetPublicKey(keyShare)
	if err != nil {
		return nil, err
	}
	return crypto.CompressPubkey(pubKey), nil
}
