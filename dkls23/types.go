// Package dkls23 implements the DKLs23 threshold ECDSA protocol.
//
// Ported to Go from https://github.com/0xCarbon/DKLs23
// Licensed under MIT/Apache-2.0 (dual license).
//
// This package provides a Paillier-free threshold ECDSA implementation
// using Oblivious Transfer (OT) for the MtA (Multiplicative-to-Additive)
// conversion, resulting in faster key generation compared to GG20.
// See https://eprint.iacr.org/2023/765.pdf for the paper.
package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/f3rmion/fy/group"
	"github.com/f3rmion/fy/secp256k1"
)

// Group is the secp256k1 group used for ECDSA
var Group = secp256k1.New()

// NewScalar creates a new zero scalar
func NewScalar() group.Scalar {
	return Group.NewScalar()
}

// NewPoint creates a new identity point
func NewPoint() group.Point {
	return Group.NewPoint()
}

// Generator returns the secp256k1 generator point
func Generator() group.Point {
	return Group.Generator()
}

// RandomScalar generates a random non-zero scalar
func RandomScalar() (group.Scalar, error) {
	return Group.RandomScalar(rand.Reader)
}

// ScalarAdd adds two scalars: result = a + b (mod n)
func ScalarAdd(a, b group.Scalar) group.Scalar {
	return NewScalar().Add(a, b)
}

// ScalarSub subtracts two scalars: result = a - b (mod n)
func ScalarSub(a, b group.Scalar) group.Scalar {
	return NewScalar().Sub(a, b)
}

// ScalarMul multiplies two scalars: result = a * b (mod n)
func ScalarMul(a, b group.Scalar) group.Scalar {
	return NewScalar().Mul(a, b)
}

// ScalarNeg negates a scalar: result = -a (mod n)
func ScalarNeg(a group.Scalar) group.Scalar {
	return NewScalar().Negate(a)
}

// ScalarInvert computes the modular inverse: result = a^(-1) (mod n)
func ScalarInvert(a group.Scalar) (group.Scalar, error) {
	return NewScalar().Invert(a)
}

// ScalarFromBytes creates a scalar from bytes
func ScalarFromBytes(data []byte) (group.Scalar, error) {
	return NewScalar().SetBytes(data)
}

// PointAdd adds two points: result = P + Q
func PointAdd(a, b group.Point) group.Point {
	return NewPoint().Add(a, b)
}

// PointSub subtracts two points: result = P - Q
func PointSub(a, b group.Point) group.Point {
	return NewPoint().Sub(a, b)
}

// ScalarMult multiplies a point by a scalar: result = k * P
func ScalarMult(p group.Point, k group.Scalar) group.Point {
	return NewPoint().ScalarMult(k, p)
}

// ScalarBaseMult multiplies the generator by a scalar: result = k * G
func ScalarBaseMult(k group.Scalar) group.Point {
	return ScalarMult(Generator(), k)
}

// PointToBytes serializes a point to bytes
func PointToBytes(p group.Point) []byte {
	return p.Bytes()
}

// PointFromBytes deserializes bytes to a point
func PointFromBytes(data []byte) (group.Point, error) {
	return NewPoint().SetBytes(data)
}

// Hash computes SHA-256 of the message with optional salt.
// Following 0xCarbon: hash(salt || msg)
func Hash(msg, salt []byte) HashOutput {
	h := sha256.New()
	h.Write(salt)
	h.Write(msg)
	var out HashOutput
	copy(out[:], h.Sum(nil))
	return out
}

// HashAsScalar hashes a message and returns the result as a scalar.
// The SHA-256 output (32 bytes) is converted to a scalar via ScalarFromBytes,
// which performs modular reduction for secp256k1. The error is safe to discard
// because 32-byte inputs are always valid for SetBytes.
func HashAsScalar(msg, salt []byte) group.Scalar {
	hash := Hash(msg, salt)
	// ScalarFromBytes reduces mod n; 32-byte SHA-256 output is always valid input.
	s, _ := ScalarFromBytes(hash[:])
	return s
}

// RandBytes generates n random bytes
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

// IsZero checks if a scalar is zero
func IsZero(s group.Scalar) bool {
	return s.IsZero()
}

// ScalarEqual checks if two scalars are equal
func ScalarEqual(a, b group.Scalar) bool {
	return a.Equal(b)
}

// PointEqual checks if two points are equal
func PointEqual(a, b group.Point) bool {
	return a.Equal(b)
}

// IsIdentity checks if a point is the identity
func IsIdentity(p group.Point) bool {
	return p.IsIdentity()
}
