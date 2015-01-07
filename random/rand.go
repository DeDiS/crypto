// Package rand provides facilities for generating
// random or pseudorandom cryptographic objects.
//
// XXX this package might go away and get subsumed by the
// currently equivalent abstract.Stream type.
package random

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Choose a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func Bits(bitlen uint, exact bool, rand cipher.Stream) []byte {
	b := make([]byte, (bitlen+7)/8)
	rand.XORKeyStream(b, b)
	highbits := bitlen & 7
	if highbits != 0 {
		b[0] &= ^(0xff << highbits)
	}
	if exact {
		if highbits != 0 {
			b[0] |= 1 << (highbits - 1)
		} else {
			b[0] |= 0x80
		}
	}
	return b
}

// Choose a uniform random byte
func Byte(rand cipher.Stream) byte {
	b := Bits(8, false, rand)
	return b[0]
}

// Choose a uniform random uint8
func Uint8(rand cipher.Stream) uint8 {
	b := Bits(8, false, rand)
	return uint8(b[0])
}

// Choose a uniform random uint16
func Uint16(rand cipher.Stream) uint16 {
	b := Bits(16, false, rand)
	return binary.BigEndian.Uint16(b)
}

// Choose a uniform random uint32
func Uint32(rand cipher.Stream) uint32 {
	b := Bits(32, false, rand)
	return binary.BigEndian.Uint32(b)
}

// Choose a uniform random uint64
func Uint64(rand cipher.Stream) uint64 {
	b := Bits(64, false, rand)
	return binary.BigEndian.Uint64(b)
}

// Choose a uniform random big.Int less than a given modulus
func Int(mod *big.Int, rand cipher.Stream) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(Bits(bitlen, false, rand))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// Choose a random n-byte slice
func Bytes(n int, rand cipher.Stream) []byte {
	b := make([]byte, n)
	rand.XORKeyStream(b, b)
	return b
}

// Reader wraps a Stream to produce an io.Reader
// that simply produces [pseudo-]random bits from the Stream when read.
// Calls to both Read() and XORKeyStream() may be made on the Reader,
// and may be interspersed.
type Reader struct {
	cipher.Stream
}

// Read [pseudo-]random bytes from the underlying Stream.
func (r Reader) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	r.Stream.XORKeyStream(dst, dst)
	return len(dst), nil
}

type randstream struct {
}

func (r *randstream) XORKeyStream(dst, src []byte) {
	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	buf := make([]byte, l)
	n, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	if n < len(buf) {
		panic("short read on infinite random stream!?")
	}

	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ buf[i]
	}
}

// Standard virtual "stream cipher" that just generates
// fresh cryptographically strong random bits.
var Stream cipher.Stream = new(randstream)
