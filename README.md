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


## DKLs23 (Threshold ECDSA)

DKLs23 is a Paillier-free threshold ECDSA protocol based on [eprint.iacr.org/2023/765](https://eprint.iacr.org/2023/765). It uses oblivious transfer instead of Paillier encryption, resulting in faster key generation.

Use this for ECDSA signatures on secp256k1 (Bitcoin/Ethereum compatible).

### Distributed Key Generation

```go
package main

import (
    "crypto/rand"
    "github.com/f3rmion/fy/dkls23/dkg"
    "github.com/f3rmion/fy/secp256k1"
)

func main() {
    g := &secp256k1.Secp256k1{}

    // Create DKG instances for each participant
    alice, _ := dkg.NewProtocol(g, rand.Reader, 1, 2)
    bob, _ := dkg.NewProtocol(g, rand.Reader, 2, 2)

    // Run the DKG protocol (exchange messages between parties)
    // ... protocol rounds ...

    // Each party obtains their key share
    aliceShare := alice.KeyShare()
    bobShare := bob.KeyShare()

    // Both shares yield the same public key
    publicKey := aliceShare.PublicKey
}
```

### Threshold Signing

```go
import "github.com/f3rmion/fy/dkls23/sign"

// Create signing sessions
aliceSigner, _ := sign.NewProtocol(g, rand.Reader, aliceShare, message)
bobSigner, _ := sign.NewProtocol(g, rand.Reader, bobShare, message)

// Run the signing protocol (exchange messages between parties)
// ... protocol rounds ...

// Obtain the final ECDSA signature
r, s := aliceSigner.Signature()
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
    pkX, pkY := shares[0].SpendingPublicKey()

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
