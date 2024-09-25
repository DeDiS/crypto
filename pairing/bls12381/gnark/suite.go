package gnark

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

var _ pairing.Suite = Suite{}

type Suite struct{}

func NewSuite() (s Suite) { return }

func (s Suite) String() string  { return "bls12381" }
func (s Suite) G1() kyber.Group { return G1 }
func (s Suite) G2() kyber.Group { return G2 }
func (s Suite) GT() kyber.Group { return GT }

func (s Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	aa, bb := p1.(*G1Elt), p2.(*G2Elt)
	var g1aff bls12381.G1Affine
	g1aff.FromJacobian(&aa.inner)
	var g2aff bls12381.G2Affine
	g2aff.FromJacobian(&bb.inner)
	gt, err := bls12381.Pair([]bls12381.G1Affine{g1aff}, []bls12381.G2Affine{g2aff})
	if err != nil {
		panic(fmt.Errorf("error in gnark pairing: %w", err))
	}

	return &GTElt{gt}
}

func (s Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	a, b := p1.(*G1Elt), p2.(*G2Elt)
	c, d := p3.(*G1Elt), p4.(*G2Elt)

	var aAff, cAff bls12381.G1Affine
	var bAff, dAff bls12381.G2Affine
	aAff.FromJacobian(&a.inner)
	bAff.FromJacobian(&b.inner)
	cAff.FromJacobian(&c.inner)
	dAff.FromJacobian(&d.inner)

	cAff.Neg(&cAff)

	out, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{aAff, cAff},
		[]bls12381.G2Affine{bAff, dAff},
	)
	if err != nil {
		panic(fmt.Errorf("error in gnark pairing: %w", err))
	}
	return out
}

func (s Suite) Read(_ io.Reader, _ ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

func (s Suite) Write(_ io.Writer, _ ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

func (s Suite) Hash() hash.Hash {
	return sha256.New()
}

func (s Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s Suite) RandomStream() cipher.Stream {
	return random.New()
}
