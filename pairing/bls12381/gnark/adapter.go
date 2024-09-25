package gnark

import (
	"go.dedis.ch/kyber/v4"
)

// SuiteBLS12381 is an adapter that implements the suites.Suite interface so that
// bls12381 can be used as a common suite to generate key pairs for instance but
// still preserves the properties of the pairing (e.g. the Pair function).
//
// It's important to note that the Point function will generate a point
// compatible with public keys only (group G2) where the signature must be
// used as a point from the group G1.
type SuiteBLS12381 struct {
	Suite
	kyber.Group
}

// NewSuiteBLS12381 makes a new BN256 suite
func NewSuiteBLS12381() *SuiteBLS12381 {
	return &SuiteBLS12381{}
}

// Point generates a point from the G2 group that can only be used
// for public keys
func (s *SuiteBLS12381) Point() kyber.Point {
	return s.G2().Point()
}

// PointLen returns the length of a G2 point
func (s *SuiteBLS12381) PointLen() int {
	return s.G2().PointLen()
}

// Scalar generates a scalar
func (s *SuiteBLS12381) Scalar() kyber.Scalar {
	return s.G1().Scalar()
}

// ScalarLen returns the length of a scalar
func (s *SuiteBLS12381) ScalarLen() int {
	return s.G1().ScalarLen()
}

// String returns the name of the suite
func (s *SuiteBLS12381) String() string {
	return "gnark.adapter"
}
