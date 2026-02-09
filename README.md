# fy

A Go library for threshold signatures with a curve-agnostic design.

fy provides implementations of threshold signature schemes including FROST (Schnorr) and DKLs23 (ECDSA), enabling t-of-n threshold signing where any t participants can collaboratively sign a message without reconstructing the private key.


## Installation

```
go get github.com/f3rmion/fy
```


## Features

- **Curve-agnostic design**: All protocols work with any elliptic curve implementing the `group.Group` interface
- **FROST**: Flexible Round-Optimized Schnorr Threshold signatures
- **DKLs23**: Paillier-free threshold ECDSA (faster than GG20)
- **Multiple curves**: Baby Jubjub (zkSNARK-friendly) and secp256k1 (Bitcoin/Ethereum)
- **Multiple hashers**: SHA-256, Blake2b, Poseidon (zkSNARK-optimized)
- **Railgun integration**: Threshold signatures compatible with `eddsa.verifyPoseidon`


## Package Structure

```
fy/
├── group/     # Abstract interfaces for cryptographic groups
├── frost/     # FROST threshold Schnorr signatures
├── dkls23/    # DKLs23 threshold ECDSA (Paillier-free)
│   ├── dkg/   # Distributed key generation
│   ├── sign/  # Threshold signing
│   ├── ot/    # Oblivious transfer
│   └── mta/   # Multiplicative-to-additive conversion
├── bjj/       # Baby Jubjub curve implementations
├── secp256k1/ # secp256k1 curve implementation
├── railgun/   # Railgun protocol adapter
└── session/   # High-level session management
```


## FROST (Threshold Schnorr)

FROST enables threshold Schnorr signatures. Use this for EdDSA-style signatures on curves like Baby Jubjub.

### Distributed Key Generation

```go
package main

import (
    "crypto/rand"
    "github.com/f3rmion/fy/bjj"
    "github.com/f3rmion/fy/frost"
)

func main() {
    // Create a 2-of-3 threshold scheme on Baby Jubjub
    g := &bjj.BJJ{}
    f, _ := frost.New(g, 2, 3)

    // Each participant creates their state
    participants := make([]*frost.Participant, 3)
    for i := range participants {
        participants[i], _ = f.NewParticipant(rand.Reader, i+1)
    }

    // Round 1: Broadcast commitments
    broadcasts := make([]*frost.Round1Data, 3)
    for i, p := range participants {
        broadcasts[i] = p.Round1Broadcast()
    }

    // Round 1: Send private shares to each other participant
    for i, sender := range participants {
        for j := 0; j < 3; j++ {
            if i == j {
                continue
            }
            privateData := f.Round1PrivateSend(sender, j+1)
            f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
        }
    }

    // Finalize: Each participant computes their key share
    keyShares := make([]*frost.KeyShare, 3)
    for i, p := range participants {
        keyShares[i], _ = f.Finalize(p, broadcasts)
    }

    // All participants now have the same group public key
    groupKey := keyShares[0].GroupKey
}
```

### Threshold Signing

```go
// Any 2 participants can sign
message := []byte("hello FROST")
signers := []*frost.KeyShare{keyShares[0], keyShares[1]}

// Round 1: Generate nonces and commitments
nonces := make([]*frost.SigningNonce, 2)
commitments := make([]*frost.SigningCommitment, 2)
for i, ks := range signers {
    nonces[i], commitments[i], _ = f.SignRound1(rand.Reader, ks)
}

// Round 2: Generate signature shares
sigShares := make([]*frost.SignatureShare, 2)
for i, ks := range signers {
    sigShares[i], _ = f.SignRound2(ks, nonces[i], message, commitments)
}

// Aggregate into final signature
sig, _ := f.Aggregate(message, commitments, sigShares)

// Anyone can verify with the group public key
valid := f.Verify(message, sig, groupKey)
```

### Using the Session API (Recommended)

The `session` package provides a simpler interface with built-in nonce safety:

```go
import "github.com/f3rmion/fy/session"

// Create participants
p1, _ := session.NewParticipant(g, 2, 3, 1)
p2, _ := session.NewParticipant(g, 2, 3, 2)
p3, _ := session.NewParticipant(g, 2, 3, 3)

// DKG Round 1
r1_1, _ := p1.GenerateRound1(rand.Reader, []int{1, 2, 3})
r1_2, _ := p2.GenerateRound1(rand.Reader, []int{1, 2, 3})
r1_3, _ := p3.GenerateRound1(rand.Reader, []int{1, 2, 3})
// Exchange broadcasts and private shares...

// Finalize DKG
result1, _ := p1.ProcessRound1(&session.Round1Input{...})
// result1.KeyShare, result1.GroupKey

// Signing with session (prevents nonce reuse)
sess, _ := p1.NewSigningSession(rand.Reader, message)
// sess.Commitment() - broadcast to other signers
share, _ := sess.Sign(allCommitments) // session consumed after this

// Aggregate
sig, _ := session.Aggregate(f, message, allCommitments, allShares)
```


## DKLs23 (Threshold ECDSA)

DKLs23 is a Paillier-free threshold ECDSA protocol based on [eprint.iacr.org/2023/765](https://eprint.iacr.org/2023/765). It uses oblivious transfer instead of Paillier encryption, resulting in faster key generation.

Use this for ECDSA signatures on secp256k1 (Bitcoin/Ethereum compatible).

### Using the Session API (Recommended)

The `session` package provides a high-level API that handles protocol phases:

```go
package main

import (
    "github.com/f3rmion/fy/session"
    "github.com/f3rmion/fy/dkls23/sign"
)

func main() {
    threshold := uint8(2)
    total := uint8(3)
    sessionID := []byte("unique-session-id")

    // Each participant creates their state
    p1, _ := session.NewDKLS23Participant(threshold, total, 1, sessionID)
    p2, _ := session.NewDKLS23Participant(threshold, total, 2, sessionID)
    p3, _ := session.NewDKLS23Participant(threshold, total, 3, sessionID)

    // Phase 1: Generate polynomials
    out1_1, _ := p1.DKGPhase1()
    out1_2, _ := p2.DKGPhase1()
    out1_3, _ := p3.DKGPhase1()
    // Exchange PolyPoints between participants...

    // Phase 2: Generate commitments and zero seeds
    // Phase 3: Reveal seeds and init multiplication
    // Phase 4: Finalize - each participant now has a signing Party

    party1 := p1.Party()
    party2 := p2.Party()
    // party1.PublicKey == party2.PublicKey (same ECDSA public key)
}
```

### Threshold Signing

```go
// Create signing sessions for 2-of-3 signing
messageHash := session.DKLS23MessageHash([]byte("hello ECDSA"))
signID := []byte("sign-session-1")

// Party 1 and Party 2 will sign (threshold = 2)
sess1, _ := session.NewDKLS23SigningSession(party1, messageHash, signID, []uint8{2})
sess2, _ := session.NewDKLS23SigningSession(party2, messageHash, signID, []uint8{1})

// Phase 1: Generate and exchange
out1_1, _ := sess1.Phase1()
out1_2, _ := sess2.Phase1()

// Phase 2: Exchange Phase1 outputs
out2_1, _ := sess1.Phase2(map[uint8]*sign.Phase1ToPhase2Transmit{2: out1_2.ToTransmit[2]})
out2_2, _ := sess2.Phase2(map[uint8]*sign.Phase1ToPhase2Transmit{1: out1_1.ToTransmit[1]})

// Phase 3: Exchange Phase2 outputs
out3_1, _ := sess1.Phase3(map[uint8]*sign.Phase2ToPhase3Transmit{2: out2_2.ToTransmit[2]})
out3_2, _ := sess2.Phase3(map[uint8]*sign.Phase2ToPhase3Transmit{1: out2_1.ToTransmit[1]})

// Phase 4: Aggregate broadcasts into final signature
allBroadcasts := []*sign.Phase3Broadcast{out3_1.Broadcast, out3_2.Broadcast}
sig, _ := sess1.Phase4(allBroadcasts, true) // true = normalize S for Bitcoin/Ethereum
// sig.R, sig.S, sig.RecoveryID
```

### Quick Sign (Testing)

For local testing with all parties in one process:

```go
parties := []*sign.Party{party1, party2} // threshold parties
sig, _ := session.DKLS23QuickSign(parties, messageHash, signID, true)
```


## Railgun Integration

For Railgun protocol compatibility, use the `railgun` package which produces signatures verifiable by circomlibjs `eddsa.verifyPoseidon`:

```go
import (
    "crypto/rand"
    "github.com/f3rmion/fy/railgun"
)

func main() {
    // Create a 2-of-3 threshold wallet
    tw, _ := railgun.NewThresholdWallet(2, 3)

    // Run DKG to generate shares
    shares, _ := tw.GenerateShares(rand.Reader)

    // Get the circomlibjs-compatible public key (A = Y/8)
    pkX, pkY, _ := shares[0].SpendingPublicKey()

    // Sign a message (e.g., Railgun sighash)
    message := sighash.Bytes() // 32-byte Poseidon hash
    sig, _ := tw.Sign(shares[:2], message)

    // Get signature components for circomlibjs verification
    rx, ry, s := sig.Components()
}
```

The signature can be verified in TypeScript:

```typescript
import { eddsa } from '@railgun-community/circomlibjs';

const pubkey: [bigint, bigint] = [pkX, pkY];
const signature = { R8: [rx, ry], S: s };

const isValid = eddsa.verifyPoseidon(message, signature, pubkey);
```


## Curves

### Baby Jubjub

Two implementations for different use cases:

| Type | Parameters | Use Case |
|------|------------|----------|
| `bjj.BJJ` | A=-1 (gnark-crypto) | General FROST signing |
| `bjj.CircomBJJ` | A=168700, D=168696 | circomlibjs/Railgun compatibility |

### secp256k1

Standard Bitcoin/Ethereum curve for ECDSA signatures:

```go
import "github.com/f3rmion/fy/secp256k1"

g := &secp256k1.Secp256k1{}
```


## Hash Functions

FROST supports multiple hashers for different use cases:

```go
// Default: SHA-256
f, _ := frost.New(g, 2, 3)

// Ledger compatible: Blake2b-512
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewBlake2bHasher())

// zkSNARK optimized: Poseidon
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewPoseidonHasher())

// Railgun compatible
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewRailgunHasher())
```

| Hasher | Use Case |
|--------|----------|
| `SHA256Hasher` | General purpose, default |
| `Blake2bHasher` | Ledger hardware wallet compatibility |
| `PoseidonHasher` | zkSNARK circuit verification |
| `RailgunHasher` | circomlibjs `eddsa.verifyPoseidon` compatibility |


## Adding a New Curve

To use threshold signatures with a different elliptic curve, implement the `group.Group` interface:

1. Implement `group.Scalar` for field elements
2. Implement `group.Point` for curve points
3. Implement `group.Group` as a factory

See the `bjj` or `secp256k1` packages for reference implementations.


## References

- FROST: Flexible Round-Optimized Schnorr Threshold Signatures
  https://eprint.iacr.org/2020/852

- DKLs23: Threshold ECDSA in Three Rounds
  https://eprint.iacr.org/2023/765

- Baby Jubjub Elliptic Curve
  https://eips.ethereum.org/EIPS/eip-2494


## License

MIT
