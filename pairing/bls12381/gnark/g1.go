package gnark

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"go.dedis.ch/kyber/v4"
)

var _ kyber.SubGroupElement = &G1Elt{}

// G1Elt is a wrapper around a G1 point on the BLS12-381 Gnark curve.
type G1Elt struct{ inner bls12381.G1Jac }

// MarshalBinary returns a compressed point, without any domain separation tag information
func (p *G1Elt) MarshalBinary() (data []byte, err error) {
	var g1aff bls12381.G1Affine
	g1aff.FromJacobian(&p.inner)
	res := g1aff.Bytes()
	return res[:], nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (p *G1Elt) UnmarshalBinary(data []byte) error {
	var g1aff bls12381.G1Affine
	_, err := g1aff.SetBytes(data)
	if err != nil {
		return fmt.Errorf("setting affine representation: %w", err)
	}

	p.inner.FromAffine(&g1aff)
	return nil
}

func (p *G1Elt) String() string { return p.inner.String() }

func (p *G1Elt) MarshalSize() int { return bls12381.SizeOfG1AffineCompressed }

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (p *G1Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (p *G1Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *G1Elt) Equal(p2 kyber.Point) bool { x := p2.(*G1Elt); return p.inner.Equal(&x.inner) }

func (p *G1Elt) Null() kyber.Point {
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	p.inner.Z.SetZero()
	return p
}

func (p *G1Elt) Base() kyber.Point {
	p.inner, _, _, _ = bls12381.Generators()
	return p
}

func (p *G1Elt) Pick(rand cipher.Stream) kyber.Point {
	var buf [32]byte
	rand.XORKeyStream(buf[:], buf[:])
	return p.Hash(buf[:])
}

func (p *G1Elt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*G1Elt).inner; return p }

func (p *G1Elt) Clone() kyber.Point { return new(G1Elt).Set(p) }

func (p *G1Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *G1Elt) Add(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*G1Elt), b.(*G1Elt)
	p.inner.Set(&aa.inner)
	p.inner.AddAssign(&bb.inner)
	return p
}

func (p *G1Elt) Sub(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*G1Elt), b.(*G1Elt)
	p.inner.Set(&aa.inner)
	p.inner.SubAssign(&bb.inner)
	return p
}

func (p *G1Elt) Neg(a kyber.Point) kyber.Point {
	p.inner.Neg(&a.(*G1Elt).inner)
	return p
}

func (p *G1Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = new(G1Elt).Base()
	}
	ss, qq := s.(*Scalar), q.(*G1Elt)
	var scalar big.Int
	ss.inner.BigInt(&scalar)
	p.inner.ScalarMultiplication(&qq.inner, &scalar)
	return p
}

func (p *G1Elt) IsInCorrectGroup() bool {
	return !(p.inner.X.IsZero() && p.inner.Y.IsZero() && p.inner.X.IsZero()) &&
		p.inner.IsOnCurve() && p.inner.IsInSubGroup()
}

var domainG1 = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

func (p *G1Elt) Hash(msg []byte) kyber.Point { return p.Hash2(msg, domainG1) }
func (p *G1Elt) Hash2(msg, dst []byte) kyber.Point {
	g1aff, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		panic(fmt.Errorf("error while hashing: %w", err))
	}
	p.inner.FromAffine(&g1aff)
	return p
}
