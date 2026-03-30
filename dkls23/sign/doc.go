// Package sign implements the DKLs23 signing protocol (Protocol 3.6).
//
// The signing protocol operates in 4 phases:
//
//   - Phase 1: Generate instance key, start MtA with each counterparty.
//   - Phase 2: Continue MtA, compute Lagrange coefficients and key shares.
//   - Phase 3: Verify MtA consistency, compute signature shares (u, w).
//   - Phase 4: Aggregate shares, compute final ECDSA signature (r, s).
//
// See https://eprint.iacr.org/2023/765.pdf for the protocol specification.
package sign
