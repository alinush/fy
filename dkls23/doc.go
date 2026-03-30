// Package dkls23 implements the DKLs23 threshold ECDSA protocol on secp256k1.
//
// The protocol uses Oblivious Transfer (OT) for the Multiplicative-to-Additive
// (MtA) conversion, avoiding Paillier encryption and achieving faster key
// generation compared to GG20. See https://eprint.iacr.org/2023/765.pdf.
//
// This package provides convenience wrappers around the secp256k1 group
// operations, hashing utilities, and type definitions used by the sub-packages:
//
//   - dkls23/ot:   Oblivious Transfer (base and extension)
//   - dkls23/mta:  Multiplicative-to-Additive conversion
//   - dkls23/sign: 4-phase signing protocol (Protocol 3.6)
//
// Ported to Go from https://github.com/0xCarbon/DKLs23
// Licensed under MIT/Apache-2.0 (dual license).
package dkls23
