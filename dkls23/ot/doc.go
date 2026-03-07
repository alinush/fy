// Package ot implements Oblivious Transfer protocols for DKLs23.
//
// It provides both base OT and OT extension:
//
//   - Base OT uses the endemic OT protocol from Zhou et al.
//     (https://eprint.iacr.org/2022/1525.pdf) as suggested in DKLs23.
//
//   - OT Extension (KOS) amortizes the cost of base OT by extending a
//     small number of base OTs (Kappa = 256) into a large batch
//     (BatchSize = 416) using pseudorandom generators and consistency
//     checks over GF(2^208).
//
// The base OT protocol operates in a sender/receiver model with
// choice-bit-based selection. The extension protocol reverses the
// OT roles: the extension sender acts as a base OT receiver and
// vice versa.
package ot
