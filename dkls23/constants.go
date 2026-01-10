// Package dkls23 implements the DKLs23 threshold ECDSA protocol.
//
// Ported to Go from https://github.com/0xCarbon/DKLs23
// Licensed under MIT/Apache-2.0 (dual license).
// Copyright 2024 0xCarbon
//
// This is a derivative work implementing the DKLs23 protocol
// (https://eprint.iacr.org/2023/765.pdf) for threshold ECDSA signatures.
package dkls23

// Security parameters from DKLs23
const (
	// RawSecurity is the computational security parameter (lambda_c) in bits.
	// Same as the Kappa parameter - bits on underlying Scalar (secp256k1).
	RawSecurity = 256

	// Security is RawSecurity divided by 8 (used for byte arrays).
	Security = RawSecurity / 8 // 32 bytes

	// StatSecurity is the statistical security parameter (lambda_s) in bits.
	StatSecurity = 80
)

// Constants for the randomized Fischlin transform (DLogProof).
const (
	// FischlinR is the number of parallel repetitions.
	FischlinR = 64

	// FischlinL is log2 of the hash output size for matching.
	FischlinL = 4

	// FischlinT is the challenge size in bits.
	FischlinT = 32
)

// PointBytesSize is the size of a compressed secp256k1 point.
const PointBytesSize = 33

// ScalarBytesSize is the size of a secp256k1 scalar.
const ScalarBytesSize = 32

// HashOutputSize is the size of SHA-256 output (same as Security).
const HashOutputSize = Security

// HashOutput represents the output of the hash function (SHA-256).
type HashOutput = [HashOutputSize]byte
