// Package golden implements the GOLDEN distributed key generation protocol
// with eVRF (encrypted Verifiable Random Function) proofs.
//
// GOLDEN produces threshold-compatible key shares on BN254 G1 with optional
// derived key shares on additional curves (e.g., Baby Jubjub, secp256k1).
// Each share is accompanied by a PLONK zero-knowledge proof (eVRF) that
// binds the recipient's identity to the encrypted share, ensuring that
// the dealer cannot equivocate (provide different shares to different
// recipients without detection).
//
// # Security Properties
//
//   - Threshold (t, n): Requires t out of n honest participants to reconstruct
//     the secret or produce a valid FROST signature. An adversary controlling
//     fewer than t shares learns nothing about the group secret key.
//
//   - Non-interactive DKG: Each dealer broadcasts a single round of messages.
//     Recipients verify VSS commitments, identity proofs, and eVRF proofs
//     independently, without further interaction.
//
//   - Verifiable secret sharing: Feldman VSS commitments allow any recipient
//     to verify that their share is consistent with the dealer's committed
//     polynomial, without learning other participants' shares.
//
//   - eVRF binding: The PLONK proof ensures the encrypted share was
//     computed correctly for the specific recipient, preventing a malicious
//     dealer from sending inconsistent shares.
//
// # Threat Model
//
//   - Honest-but-curious adversary for confidentiality: The protocol does
//     not prevent a malicious dealer from choosing a biased polynomial,
//     but honest recipients can detect inconsistent shares via VSS.
//
//   - Active adversary for integrity: VSS and eVRF proofs protect against
//     a malicious dealer sending invalid or inconsistent shares.
//
//   - The SRS (Structured Reference String) used for PLONK proofs must
//     come from a trusted setup ceremony (Aztec Ignition). Test code
//     overrides the SRS provider via testingSRSProvider in _test.go;
//     the production code path cannot be switched at runtime.
//
// # Integration
//
// After DKG completes, use [DkgOutputToKeyShare] or [DkgOutputToDerivedKeyShare]
// to convert the output into FROST KeyShares for threshold signing.
package golden
