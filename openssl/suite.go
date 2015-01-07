// Package openssl implements a ciphersuite
// based on OpenSSL's crypto library.
package openssl

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sha3"
	"hash"
)

type suite128 struct {
	curve
}

func (s *suite128) String() string {
	return "P256"
}

func (s *suite128) HashLen() int {
	return 32 // SHA256_DIGEST_LENGTH
}

func (s *suite128) Hash() hash.Hash {
	return NewSHA256()
}

func (s *suite128) KeyLen() int {
	return 16 // AES128
}

func (s *suite128) Stream(key []byte) cipher.Stream {
	if len(key) != 16 {
		panic("wrong AES key size")
	}
	return abstract.BlockStream(NewAES(key), nil)
}

func (s *suite128) Sponge() abstract.Sponge {
	return sha3.NewSponge128()
}

// Ciphersuite based on AES-128, SHA-256, and the NIST P-256 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES128SHA256P256() abstract.Suite {
	s := new(suite128)
	s.curve.InitP256()
	return s
}

type suite192 struct {
	curve
}

func (s *suite192) String() string {
	return "AES192SHA384P384"
}

func (s *suite192) HashLen() int {
	return 48 // SHA384_DIGEST_LENGTH
}

func (s *suite192) Hash() hash.Hash {
	return NewSHA384()
}

func (s *suite192) KeyLen() int {
	return 24 // AES192
}

func (s *suite192) Stream(key []byte) cipher.Stream {
	if len(key) != 24 {
		panic("wrong AES key size")
	}
	return abstract.BlockStream(NewAES(key), nil)
}

func (s *suite192) Sponge() abstract.Sponge {
	return sha3.NewSponge256()
}

// Ciphersuite based on AES-192, SHA-384, and the NIST P-384 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES192SHA384P384() abstract.Suite {
	s := new(suite192)
	s.curve.InitP384()
	return s
}

type suite256 struct {
	curve
}

func (s *suite256) String() string {
	return "AES256SHA512P521"
}

func (s *suite256) HashLen() int {
	return 64 // SHA512_DIGEST_LENGTH
}

func (s *suite256) Hash() hash.Hash {
	return NewSHA512()
}

func (s *suite256) KeyLen() int {
	return 32 // AES256
}

func (s *suite256) Sponge() abstract.Sponge {
	return sha3.NewSponge256()
}

func (s *suite256) Stream(key []byte) cipher.Stream {
	if len(key) != 32 {
		panic("wrong AES key size")
	}
	return abstract.BlockStream(NewAES(key), nil)
}

// Ciphersuite based on AES-256, SHA-512, and the NIST P-521 elliptic curve,
// using the implementations in OpenSSL's crypto library.
func NewAES256SHA512P521() abstract.Suite {
	s := new(suite256)
	s.curve.InitP521()
	return s
}
