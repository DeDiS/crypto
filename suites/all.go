package suites

import (
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func init() {
	// Those are variable time suites that shouldn't be used
	// in production environment when possible
	register(nist.NewBlakeSHA256P256())
	register(nist.NewBlakeSHA256QR512())
	register(bn256.NewSuiteG1())
	register(bn256.NewSuiteG2())
	register(bn256.NewSuiteGT())
	register(bn256.NewSuiteBn256())
	register(circl.NewSuiteBLS12381())
	register(kilic.NewSuiteBLS12381())
	// This is a constant time implementation that should be
	// used as much as possible
	register(edwards25519.NewBlakeSHA256Ed25519())
}
