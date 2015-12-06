// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file defines the ShakeHash interface, and provides
// functions for creating SHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
	"io"
)

// ShakeHash defines the interface to hash functions that
// support arbitrary-length output.
type ShakeHash interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	io.Reader

	// Clone returns a copy of the ShakeHash in its current state.
	Clone() ShakeHash

	// Reset resets the ShakeHash to its initial state.
	Reset()
}

// Simple implementation of the ShakeHash interface
// as a special-case use of the Message Cipher interface.
type shake struct {
	sponge    func() cipher.Sponge
	cipher    abstract.Cipher
	squeezing bool
}

func newShake(sponge func() cipher.Sponge) ShakeHash {
	sh := &shake{sponge: sponge}
	sh.Reset()
	return sh
}

func (s *shake) Write(src []byte) (int, error) {
	if s.squeezing {
		panic("sha3: write to SHAKE after read")
	}
	return s.cipher.Write(src)
}

func (s *shake) Read(dst []byte) (int, error) {

	// If we're still absorbing, complete the absorbed message
	if !s.squeezing {
		s.cipher.Message(nil, nil, nil)
		s.squeezing = true
	}

	// Now, squeeze bytes into the dst buffer.
	return s.cipher.Read(dst)
}

func (s *shake) Clone() ShakeHash {
	ns := *s
	ns.cipher = s.cipher.Clone()
	return &ns
}

func (s *shake) Reset() {
	s.cipher.State = cipher.FromSponge(s.sponge(), abstract.NoKey)
	s.cipher.State.(cipher.Padding).SetPadding(shakePadding)
	s.squeezing = false
}

const shakePadding byte = 0x1f // Padding byte defined for SHAKE schemes

// NewShakeCipher128 creates a Cipher implementing the SHAKE128 algorithm,
// which provides 128-bit security against all known attacks.
func NewShakeCipher128(key []byte) cipher.State {
	c := cipher.FromSponge(newKeccak256(), key)
	c.(cipher.Padding).SetPadding(shakePadding)
	return c
}

// NewShakeCipher256 creates a Cipher implementing the SHAKE256 algorithm,
// which provides 256-bit security against all known attacks.
func NewShakeCipher256(key []byte) cipher.State {
	c := cipher.FromSponge(newKeccak512(), key)
	c.(cipher.Padding).SetPadding(shakePadding)
	return c
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() ShakeHash { return newShake(newKeccak256) }

// NewShake256 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() ShakeHash { return newShake(newKeccak512) }

// ShakeSum128 writes an arbitrary-length digest of data into hash.
func ShakeSum128(hash, data []byte) {
	h := NewShake128()
	h.Write(data)
	h.Read(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	h.Write(data)
	h.Read(hash)
}

type suite128 struct{}

func (_ suite128) Cipher(key []byte) cipher.State {
	return NewShakeCipher128(key)
}

// Create a context configured with Shake256 as the symmetric cipher.
func WithShake128(parent abstract.Context) abstract.Context {
	return cipher.Context(parent, suite128{})
}

type suite256 struct{}

func (_ suite256) Cipher(key []byte) cipher.State {
	return NewShakeCipher256(key)
}

// Create a context configured with Shake256 as the symmetric cipher.
func WithShake256(parent abstract.Context) abstract.Context {
	return cipher.Context(parent, suite256{})
}
