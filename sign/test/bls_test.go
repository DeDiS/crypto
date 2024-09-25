package test

import (
	"testing"

	"go.dedis.ch/kyber/v4/internal/test"
	circl "go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	"go.dedis.ch/kyber/v4/pairing/bls12381/gnark"
	kilic "go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	sign "go.dedis.ch/kyber/v4/sign/bls"
)

func TestCirclBLS12381(t *testing.T) {
	suite := circl.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}

func TestKilicBLS12381(t *testing.T) {
	suite := kilic.NewBLS12381Suite()
	scheme := sign.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}

func TestGnarkBLS12381G1(t *testing.T) {
	suite := gnark.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}

func TestGnarkBLS12381G2(t *testing.T) {
	suite := gnark.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}
