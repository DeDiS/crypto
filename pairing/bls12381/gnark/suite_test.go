package gnark

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"go.dedis.ch/kyber/v4/pairing"

	"go.dedis.ch/kyber/v4"
)

func TestVerifySigOnG2(t *testing.T) {
	pk := "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"
	sig := "8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655"
	prevSig := "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
	round := uint64(1)

	suite := NewSuite()
	pkb, _ := hex.DecodeString(pk)
	pubkeyP := suite.G1().Point()
	pubkeyP.UnmarshalBinary(pkb)
	sigb, _ := hex.DecodeString(sig)
	sigP := suite.G2().Point()
	sigP.UnmarshalBinary(sigb)
	prev, _ := hex.DecodeString(prevSig)
	h := sha256.New()
	h.Write(prev)
	_ = binary.Write(h, binary.BigEndian, round)
	msg := h.Sum(nil)

	base := suite.G1().Point().Base().Clone()
	MsgP := suite.G2().Point().(kyber.HashablePoint).Hash(msg)
	if !suite.ValidatePairing(base, sigP, pubkeyP, MsgP) {
		t.Fatalf("Error validating pairing")
	}
}

func TestImplementInterfaces(_ *testing.T) {
	var _ kyber.Point = &G1Elt{}
	var _ kyber.Point = &G2Elt{}
	var _ kyber.Point = &GTElt{}
	var _ kyber.HashablePoint = &G1Elt{}
	var _ kyber.HashablePoint = &G2Elt{}
	// var _ kyber.hashablePoint = &KyberGT{} // GT is not hashable for now
	var _ kyber.Group = &groupBls{}
	var _ pairing.Suite = &Suite{}
}
