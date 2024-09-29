package circl

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/cloudflare/circl/ecc/bls12381"
	"go.dedis.ch/kyber/v4"
)

var _ kyber.Scalar = &Scalar{}

type Scalar struct{ inner bls12381.Scalar }

func (s *Scalar) MarshalBinary() (data []byte, err error) { return s.inner.MarshalBinary() }

func (s *Scalar) UnmarshalBinary(data []byte) error { return s.inner.UnmarshalBinary(data) }

func (s *Scalar) String() string { return s.inner.String() }

func (s *Scalar) MarshalSize() int { return bls12381.ScalarSize }

func (s *Scalar) MarshalTo(w io.Writer) (int, error) {
	buf, err := s.inner.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (s *Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.inner.UnmarshalBinary(buf)
}

func (s *Scalar) Equal(s2 kyber.Scalar) bool {
	x := s2.(*Scalar)
	return s.inner.IsEqual(&x.inner) == 1
}

func (s *Scalar) Set(a kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar)
	s.inner.Set(&aa.inner)
	return s
}

func (s *Scalar) Clone() kyber.Scalar { return new(Scalar).Set(s) }

func (s *Scalar) SetInt64(v int64) kyber.Scalar {
	if v >= 0 {
		s.inner.SetUint64(uint64(v))
	} else {
		s.inner.SetUint64(uint64(-v))
		s.inner.Neg()
	}

	return s
}

func (s *Scalar) SetIntString(v string) (kyber.Scalar, error) {
	err := s.inner.SetString(v)
	if err != nil {
		return nil, fmt.Errorf("unable to set string number: %v", err)
	}
	return s, nil
}

func (s *Scalar) Zero() kyber.Scalar { s.inner.SetUint64(0); return s }

func (s *Scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	aa, bb := a.(*Scalar), b.(*Scalar)
	s.inner.Add(&aa.inner, &bb.inner)
	return s
}

func (s *Scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	aa, bb := a.(*Scalar), b.(*Scalar)
	s.inner.Sub(&aa.inner, &bb.inner)
	return s
}

func (s *Scalar) Neg(a kyber.Scalar) kyber.Scalar {
	s.Set(a)
	s.inner.Neg()
	return s
}

func (s *Scalar) One() kyber.Scalar { s.inner.SetUint64(1); return s }

func (s *Scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	aa, bb := a.(*Scalar), b.(*Scalar)
	s.inner.Mul(&aa.inner, &bb.inner)
	return s
}

func (s *Scalar) Div(a, b kyber.Scalar) kyber.Scalar { return s.Mul(new(Scalar).Inv(b), a) }

func (s *Scalar) Inv(a kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar)
	s.inner.Inv(&aa.inner)
	return s
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func (s *Scalar) Pick(stream cipher.Stream) kyber.Scalar {
	err := s.inner.Random(cipher.StreamReader{S: stream, R: zeroReader{}})
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Scalar) SetBytes(data []byte) kyber.Scalar { s.inner.SetBytes(data); return s }

func (s *Scalar) ByteOrder() kyber.ByteOrder {
	return kyber.BigEndian
}

func (s *Scalar) GroupOrder() *big.Int {
	return big.NewInt(0).SetBytes(bls12381.Order())
}
