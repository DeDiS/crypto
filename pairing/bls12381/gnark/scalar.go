package gnark

import (
	"crypto/cipher"
	"io"
	"math/big"

	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/util/random"
)

var _ kyber.Scalar = &Scalar{}

type Scalar struct{ inner fr.Element }

func (s *Scalar) MarshalBinary() (data []byte, err error) { res := s.inner.Bytes(); return res[:], nil }

func (s *Scalar) UnmarshalBinary(data []byte) error { s.inner.SetBytes(data); return nil }

func (s *Scalar) String() string { return s.inner.String() }

func (s *Scalar) MarshalSize() int { return fr.Bytes }

func (s *Scalar) MarshalTo(w io.Writer) (int, error) {
	buf := s.inner.Bytes()
	return w.Write(buf[:])
}

func (s *Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	s.inner.SetBytes(buf)
	return n, nil
}

func (s *Scalar) Equal(s2 kyber.Scalar) bool {
	x := s2.(*Scalar)
	return s.inner.Cmp(&x.inner) == 0
}

func (s *Scalar) Set(a kyber.Scalar) kyber.Scalar {
	aa := a.(*Scalar)
	s.inner.Set(&aa.inner)
	return s
}

func (s *Scalar) Clone() kyber.Scalar { return new(Scalar).Set(s) }

func (s *Scalar) SetInt64(v int64) kyber.Scalar {
	s.inner.SetInt64(v)

	return s
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
	s.inner.Neg(&s.inner)
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
	s.inner.Inverse(&aa.inner)
	return s
}

func (s *Scalar) Pick(stream cipher.Stream) kyber.Scalar {
	n := random.Int(fr.Modulus(), stream)
	s.inner.SetBigInt(n)
	return s
}

func (s *Scalar) SetBytes(data []byte) kyber.Scalar { s.inner.SetBytes(data); return s }

func (s *Scalar) ByteOrder() kyber.ByteOrder {
	return kyber.BigEndian
}

func (s *Scalar) GroupOrder() *big.Int {
	return fr.Modulus()
}
