# fy

A Go library implementing the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme with a curve-agnostic design.

FROST enables t-of-n threshold signatures where any t participants can collaboratively sign a message without reconstructing the private key. This implementation includes Baby Jubjub elliptic curve adapters, making it suitable for use in zero-knowledge proof systems and privacy-preserving applications like Railgun.


## Installation

```
go get github.com/f3rmion/fy
```


## Features

- **Curve-agnostic FROST**: Works with any elliptic curve implementing the `group.Group` interface
- **Baby Jubjub support**: Two implementations for different use cases:
  - `BJJ`: Standard implementation using gnark-crypto (A=-1 parameterization)
  - `CircomBJJ`: circomlibjs-compatible implementation (A=168700, D=168696)
- **Multiple hashers**: SHA-256, Blake2b (Ledger-compatible), Poseidon (zkSNARK-optimized), and Railgun-compatible
- **Railgun integration**: Threshold signatures compatible with `eddsa.verifyPoseidon`
- **Session management**: High-level API for multi-party signing sessions


## Usage

### Distributed Key Generation

Before signing, participants run a distributed key generation (DKG) protocol to establish their key shares:

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

Once key shares are established, any t participants can sign a message:

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

### Railgun Integration

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

The signature can be verified in TypeScript with circomlibjs:

```typescript
import { eddsa } from '@railgun-community/circomlibjs';

const pubkey: [bigint, bigint] = [pkX, pkY];
const signature = { R8: [rx, ry], S: s };

const isValid = eddsa.verifyPoseidon(message, signature, pubkey);
```

### Hash Function Configuration

FROST uses hash functions for binding factors and Schnorr challenges. Multiple hashers are available:

```go
// Default: SHA-256 hasher
f, _ := frost.New(g, 2, 3)

// Ledger compatible: Blake2b-512 with domain separation
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewBlake2bHasher())

// zkSNARK optimized: Poseidon hash
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewPoseidonHasher())

// Railgun compatible: Poseidon with circomlibjs challenge computation
f, _ := frost.NewWithHasher(g, 2, 3, frost.NewRailgunHasher())
```

| Hasher | Use Case |
|--------|----------|
| `SHA256Hasher` | General purpose, default |
| `Blake2bHasher` | Ledger hardware wallet compatibility |
| `PoseidonHasher` | zkSNARK circuit verification |
| `RailgunHasher` | circomlibjs `eddsa.verifyPoseidon` compatibility |

You can implement custom hashers by satisfying the Hasher interface:

```go
type Hasher interface {
    H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar  // binding factor
    H2(g group.Group, R, Y, msg []byte) group.Scalar                     // Schnorr challenge
    H3(g group.Group, seed, rho, msg []byte) group.Scalar                // nonce generation
    H4(g group.Group, msg []byte) []byte                                 // message hash
    H5(g group.Group, encCommitList []byte) []byte                       // commitment hash
}
```


## Package Structure

```
fy/
├── group/    # Abstract interfaces for cryptographic groups
├── bjj/      # Baby Jubjub curve implementations
├── frost/    # FROST threshold signature protocol
├── railgun/  # Railgun protocol adapter
├── session/  # High-level session management
├── go.mod
└── go.sum
```

### group

Defines the core interfaces that abstract over elliptic curve operations:

- `Group`: Factory for scalars and points, provides the generator and random scalar generation
- `Scalar`: Field element arithmetic (add, subtract, multiply, invert)
- `Point`: Group element operations (add, subtract, scalar multiplication)

### bjj

Implements the group interfaces for Baby Jubjub twisted Edwards curves:

| Type | Curve Parameters | Generator | Use Case |
|------|------------------|-----------|----------|
| `BJJ` | A=-1 (gnark-crypto) | Standard | General FROST signing |
| `CircomBJJ` | A=168700, D=168696 | Base8 | circomlibjs/Railgun compatibility |

**CircomBJJ** uses the same curve parameters as `@railgun-community/circomlibjs`, enabling signatures that verify with `eddsa.verifyPoseidon`.

### frost

Implements the FROST protocol with two main phases:

- **Distributed Key Generation (DKG)**: Participants jointly generate key shares without a trusted dealer
- **Threshold Signing**: Any t-of-n participants can collaboratively produce a valid Schnorr signature

The implementation is curve-agnostic and accepts any `group.Group` implementation.

### railgun

Provides a high-level adapter for Railgun protocol integration:

- `ThresholdWallet`: Manages FROST threshold signing for Railgun transactions
- `Signature`: Railgun-compatible signature format (R.x, R.y, S)
- `SpendingPublicKey()`: Returns the circomlibjs-compatible public key (Y/8)
- Key derivation utilities for viewing keys, master public keys, and nullifiers

### session

High-level session management for coordinating multi-party signing:

- `Session`: Manages the state of a signing session across multiple participants
- Handles commitment collection, message distribution, and signature aggregation


## Baby Jubjub Curve Compatibility

This library supports two Baby Jubjub parameterizations:

### Standard (gnark-crypto)
```
Curve: -x² + y² = 1 + d·x²·y²
A = -1
D = 12181644023421730124874158521699555681764249180949974110617291017600649128846
```

### circomlibjs
```
Curve: A·x² + y² = 1 + D·x²·y²
A = 168700
D = 168696
Generator = Base8 (cofactor-cleared point)
```

The circomlibjs parameterization is required for Railgun compatibility because `eddsa.verifyPoseidon` uses:
- Challenge: `c = poseidon([R.x, R.y, A.x, A.y, msg])`
- Verification: `S * Base8 = R + (c * 8) * A`

Where `A = Y/8` (the FROST group key divided by 8).


## Adding a New Curve

To use FROST with a different elliptic curve:

1. Implement `group.Scalar` for your field elements
2. Implement `group.Point` for your curve points
3. Implement `group.Group` as a factory

See the `bjj` package for reference implementations.


## References

- FROST: Flexible Round-Optimized Schnorr Threshold Signatures
  https://eprint.iacr.org/2020/852

- Baby Jubjub Elliptic Curve
  https://eips.ethereum.org/EIPS/eip-2494

- circomlibjs
  https://github.com/iden3/circomlibjs


## License

MIT
