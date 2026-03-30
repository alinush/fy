// Package mta implements the Multiplicative-to-Additive (MtA) conversion
// using Oblivious Transfer as described in DKLs23.
//
// MtA allows two parties holding secret scalars a and b to jointly compute
// additive shares c_A and c_B such that c_A + c_B = a * b, without revealing
// a or b to each other. This is the core building block for the DKLs23
// threshold ECDSA signing protocol.
//
// This realizes Functionality 3.5 in DKLs23 (https://eprint.iacr.org/2023/765.pdf)
// and is based on Protocol 1 of DKLs19 (https://eprint.iacr.org/2019/523.pdf).
package mta
