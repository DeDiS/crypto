package gnark

import (
	"crypto/cipher"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"go.dedis.ch/kyber/v4"
)

var gtBase *bls12381.GT

func init() {
	_, _, g1, g2 := bls12381.Generators()
	gt, err := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
	if err != nil {
		panic(err)
	}
	gtBase = &gt
}

var _ kyber.Point = &GTElt{}

// GTElt is a wrapper around the Circl Gt point type.
type GTElt struct{ inner bls12381.GT }

// MarshalBinary returns a compressed point, without any domain separation tag information
func (p *GTElt) MarshalBinary() (data []byte, err error) {
	res := p.inner.Bytes()
	return res[:], nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (p *GTElt) UnmarshalBinary(data []byte) error { return p.inner.Unmarshal(data) }

func (p *GTElt) String() string { return p.inner.String() }

func (p *GTElt) MarshalSize() int { return bls12381.SizeOfGT }

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (p *GTElt) MarshalTo(w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (p *GTElt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

func (p *GTElt) Equal(p2 kyber.Point) bool { x := p2.(*GTElt); return p.inner.Equal(&x.inner) }

func (p *GTElt) Null() kyber.Point { p.inner.SetOne(); return p }

func (p *GTElt) Base() kyber.Point { p.inner = *gtBase; return p }

func (p *GTElt) Pick(_ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Set(p2 kyber.Point) kyber.Point { p.inner = p2.(*GTElt).inner; return p }

func (p *GTElt) Clone() kyber.Point { return new(GTElt).Set(p) }

func (p *GTElt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (p *GTElt) Add(a, b kyber.Point) kyber.Point {
	aa, bb := a.(*GTElt), b.(*GTElt)
	p.inner.Mul(&aa.inner, &bb.inner)
	return p
}

func (p *GTElt) Sub(a, b kyber.Point) kyber.Point {
	return p.Add(a, new(GTElt).Neg(b))
}

func (p *GTElt) Neg(a kyber.Point) kyber.Point {
	aa := a.(*GTElt)
	p.inner.Inverse(&aa.inner)
	return p
}

func (p *GTElt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	qq, ss := q.(*GTElt), s.(*Scalar)
	var scalar big.Int
	ss.inner.BigInt(&scalar)
	p.inner.Exp(qq.inner, &scalar)
	return p
}
