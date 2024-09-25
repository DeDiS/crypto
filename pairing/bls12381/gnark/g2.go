package gnark

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"go.dedis.ch/kyber/v4"
)

var _ kyber.SubGroupElement = &G2Elt{}

// G2Elt is a wrapper around the Gnark G2 point type.
type G2Elt struct{ inner bls12381.G2Jac }

// MarshalBinary returns a compressed point, without any domain separation tag information
func (p *G2Elt) MarshalBinary() (data []byte, err error) {
	var g2aff bls12381.G2Affine
	g2aff.FromJacobian(&p.inner)
	res := g2aff.Bytes()
	return res[:], nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (p *G2Elt) UnmarshalBinary(data []byte) error {
	var g2aff bls12381.G2Affine
	_, err := g2aff.SetBytes(data)
	if err != nil {
		return fmt.Errorf("setting affine representation: %w", err)
	}

	p.inner.FromAffine(&g2aff)
	return nil
}

func (p *G2Elt) String() string { return p.inner.String() }

func (p *G2Elt) MarshalSize() int { return bls12381.SizeOfG2AffineCompressed }

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (p *G2Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (p *G2Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *G2Elt) Equal(p2 kyber.Point) bool { x := p2.(*G2Elt); return p.inner.Equal(&x.inner) }

func (p *G2Elt) Null() kyber.Point {
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	p.inner.Z.SetZero()
	return p
}

func (p *G2Elt) Base() kyber.Point {
	_, p.inner, _, _ = bls12381.Generators()
	return p
}

func (p *G2Elt) Pick(rand cipher.Stream) kyber.Point {
	var buf [32]byte
	rand.XORKeyStream(buf[:], buf[:])
	return p.Hash(buf[:])
}

func (p *G2Elt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*G2Elt).inner; return p }

func (p *G2Elt) Clone() kyber.Point { return new(G2Elt).Set(p) }

func (p *G2Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *G2Elt) Add(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*G2Elt), b.(*G2Elt)
	p.inner.Set(&aa.inner)
	p.inner.AddAssign(&bb.inner)
	return p
}

func (p *G2Elt) Sub(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*G2Elt), b.(*G2Elt)
	p.inner.Set(&aa.inner)
	p.inner.SubAssign(&bb.inner)
	return p
}

func (p *G2Elt) Neg(a kyber.Point) kyber.Point {
	p.inner.Neg(&a.(*G2Elt).inner)
	return p
}

func (p *G2Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = new(G2Elt).Base()
	}
	ss, qq := s.(*Scalar), q.(*G2Elt)
	var scalar big.Int
	ss.inner.BigInt(&scalar)
	p.inner.ScalarMultiplication(&qq.inner, &scalar)
	return p
}

func (p *G2Elt) IsInCorrectGroup() bool {
	return !(p.inner.X.IsZero() && p.inner.Y.IsZero() && p.inner.X.IsZero()) &&
		p.inner.IsOnCurve() && p.inner.IsInSubGroup()
}

var domainG2 = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

func (p *G2Elt) Hash(msg []byte) kyber.Point { return p.Hash2(msg, domainG2) }
func (p *G2Elt) Hash2(msg, dst []byte) kyber.Point {
	g1aff, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		panic(fmt.Errorf("error while hashing: %w", err))
	}
	p.inner.FromAffine(&g1aff)
	return p
}
