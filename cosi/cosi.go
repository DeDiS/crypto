/*
Package cosi implements the collective signing (CoSi) algorithm as presented in
the paper "Keeping Authorities 'Honest or Bust' with Decentralized Witness
Cosigning" by Ewa Syta et al., see https://arxiv.org/abs/1503.08768.  This
package **only** provides the functionality for the cryptographic operations of
CoSi. All network-related operations have to be handled elsewhere.  Below we
describe a high-level overview of the CoSi protocol (using a star communication
topology). We refer to the research paper for further details on communication
over trees, exception mechanisms and signature verification policies.

The CoSi protocol has four phases executed between a list of participants P
having a protocol leader (index i = 0) and a list of other nodes (index i > 0).
The secret key of node i is denoted by a_i and the public key by A_i = [a_i]G
(where G is the base point of the underlying group and [...] denotes scalar
multiplication). The aggregate public key is given as A = \sum{i ∈ P}(A_i).

1. Announcement: The leader broadcasts an announcement to the other nodes
optionally including the message M to be signed. Upon receiving an announcement
message, a node starts its commitment phase.

2. Commitment: Each node i picks a random scalar v_i, computes its commitment
V_i = [v_i]G and sends V_i back to the leader. The leader waits until it has
received enough commitments (according to some policy) from the other nodes or
a timer has run out. Let P' be the nodes that have sent their commitments. The
leader computes an aggregate commitment V from all commitments he has received,
i.e., V = \sum{j ∈ P'}(V_j) and creates a participation bitmask Z. The leader
then broadcasts V and Z to the other participations together with the message M
if it was not sent in phase 1. Upon receiving a commitment message, a node
starts the challenge phase.

3. Challenge: Each node i computes the collective challenge c = H(V || A || Z
|| M) using a cryptographic hash function H (here: SHA512), computes its
response r_i = v_i + c*a_i and sends it back to the leader.

4. Response: The leader waits until he has received replies from all nodes in
P' or a timer has run out. If he has not enough replies he aborts. Finally,
the leader computes the aggregate response r = \sum{j ∈ P'}(r_j) and publishes
(V,r,Z) as the signature for the message M.
*/
package cosi

import (
	"crypto/cipher"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/random"
)

// Commit returns a random scalar and a corresponding commitment from the given
// cipher stream.
func Commit(suite abstract.Suite, s cipher.Stream) (abstract.Scalar, abstract.Point) {
	var stream = s
	if s == nil {
		stream = random.Stream
	}
	random := suite.Scalar().Pick(stream)
	commitment := suite.Point().Mul(nil, random)
	return random, commitment
}

// AggregateCommitments returns the sum of the given commitments and the
// bitwise OR of the given masks.
func AggregateCommitments(suite abstract.Suite, commitments []abstract.Point, masks [][]byte) (abstract.Point, []byte, error) {
	if len(commitments) != len(masks) {
		return nil, nil, errors.New("mismatching lengths of commitment and mask slices")
	}
	aggCom := suite.Point().Null()
	aggMask := make([]byte, len(masks[0]))
	var err error
	for i := 0; i < len(commitments); i++ {
		aggCom = suite.Point().Add(aggCom, commitments[i])
		aggMask, err = AggregateMasks(aggMask, masks[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return aggCom, aggMask, nil
}

// Challenge creates the collective challenge from the given aggregate
// commitment V, aggregate public key A, mask Z, and message M, i.e., it
// returns c = H(V || A || Z || M).
func Challenge(suite abstract.Suite, commitment abstract.Point, mask *Mask, message []byte) (abstract.Scalar, error) {
	hash := sha512.New()
	if _, err := commitment.MarshalTo(hash); err != nil {
		return nil, err
	}
	if _, err := mask.AggregatePublic.MarshalTo(hash); err != nil {
		return nil, err
	}
	hash.Write(mask.mask)
	hash.Write(message)
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

// Response creates the response from the given random scalar v, (collective)
// challenge c, and private key a, i.e., it returns r = v + c*a.
func Response(suite abstract.Suite, random abstract.Scalar, challenge abstract.Scalar, private abstract.Scalar) (abstract.Scalar, error) {
	if private == nil {
		return nil, errors.New("no private key provided")
	}
	if random == nil {
		return nil, errors.New("no random scalar provided")
	}
	if challenge == nil {
		return nil, errors.New("no challenge provided")
	}
	ca := suite.Scalar().Mul(private, challenge)
	return ca.Add(random, ca), nil
}

// AggregateResponses returns the sum of given responses.
func AggregateResponses(suite abstract.Suite, responses []abstract.Scalar) (abstract.Scalar, error) {
	if responses == nil {
		return nil, errors.New("empty list of responses")
	}
	r := responses[0]
	for i := 1; i < len(responses); i++ {
		r = suite.Scalar().Add(r, responses[i])
	}
	return r, nil
}

// Sign returns the collective signature from the given (aggregate) commitment
// V, (aggregate) response r, and participation bitmask Z using the EdDSA
// format, i.e., the signature is V || r || Z.
func Sign(suite abstract.Suite, commitment abstract.Point, response abstract.Scalar, mask *Mask) ([]byte, error) {
	lenV := suite.PointLen()
	lenSig := lenV + suite.ScalarLen()
	VB, err := commitment.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling of commitment failed")
	}
	RB, err := response.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling of signature failed")
	}
	sig := make([]byte, lenSig+mask.MaskLen())
	copy(sig[:], VB)
	copy(sig[lenV:lenSig], RB)
	copy(sig[lenSig:], mask.mask)
	return sig, nil
}

// Verify checks the given cosignature on the provided message using the list
// of public keys and cosigning policy.
func Verify(suite abstract.Suite, publics []abstract.Point, message, sig []byte, policy Policy) error {

	if policy == nil {
		policy = CompletePolicy{}
	}

	lenCom := suite.PointLen()
	VBuff := sig[:lenCom]
	V := suite.Point()
	if err := V.UnmarshalBinary(VBuff); err != nil {
		panic(err)
	}

	// Unpack the aggregate response
	lenRes := lenCom + suite.ScalarLen()
	rBuff := sig[lenCom:lenRes]
	r := suite.Scalar().SetBytes(rBuff)

	// Unpack the participation mask and get the aggregate public key
	mask, err := NewMask(suite, publics, nil)
	if err != nil {
		return err
	}
	mask.SetMask(sig[lenRes:])
	A := mask.AggregatePublic
	ABuff, err := A.MarshalBinary()
	if err != nil {
		return err
	}

	// Recompute the challenge
	hash := sha512.New()
	hash.Write(VBuff)
	hash.Write(ABuff)
	hash.Write(mask.mask)
	hash.Write(message)
	buff := hash.Sum(nil)
	k := suite.Scalar().SetBytes(buff)

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := suite.Point().Neg(A)
	kA := suite.Point().Mul(minusPublic, k)
	sB := suite.Point().Mul(nil, r)
	left := suite.Point().Add(kA, sB)

	x, err := left.MarshalBinary()
	if err != nil {
		return err
	}
	y, err := V.MarshalBinary()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(x, y) == 0 || !policy.Check(mask) {
		return errors.New("signature invalid")
	}
	return nil
}

// Mask represents a cosigning participation bitmask.
type Mask struct {
	mask            []byte
	publics         []abstract.Point
	AggregatePublic abstract.Point
}

// NewMask returns a new participation bitmask for cosigning where all
// cosigners are disabled by default. If a public key is given it verifies that
// it is present in the list of keys and sets the corresponding index in the
// bitmask to 1 (enabled).
func NewMask(suite abstract.Suite, publics []abstract.Point, myKey abstract.Point) (*Mask, error) {
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.MaskLen())
	m.AggregatePublic = suite.Point().Null()
	if myKey != nil {
		found := false
		for i, key := range publics {
			if key.Equal(myKey) {
				m.SetMaskBit(i, true)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("key not found")
		}
	}
	return m, nil
}

// Mask returns a copy of the participation bitmask.
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone[:], m.mask)
	return clone
}

// SetMask sets the participation bitmask according to the given byte slice
// interpreted in little-endian order, i.e., bits 0-7 of byte 0 correspond to
// cosigners 0-7, bits 0-7 of byte 1 correspond to cosigners 8-15, etc.
func (m *Mask) SetMask(mask []byte) error {
	if m.MaskLen() != len(mask) {
		return fmt.Errorf("mismatching mask lengths")
	}
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if ((m.mask[byt] & msk) == 0) && ((mask[byt] & msk) != 0) {
			m.mask[byt] ^= msk // flip bit in mask from 0 to 1
			m.AggregatePublic.Add(m.AggregatePublic, m.publics[i])
		}
		if ((m.mask[byt] & msk) != 0) && ((mask[byt] & msk) == 0) {
			m.mask[byt] ^= msk // flip bit in mask from 1 to 0
			m.AggregatePublic.Sub(m.AggregatePublic, m.publics[i])
		}
	}
	return nil
}

// MaskLen returns the mask length in bytes.
func (m *Mask) MaskLen() int {
	return (len(m.publics) + 7) >> 3
}

// SetMaskBit enables (enable: true) or disables (enable: false) the bit
// in the participation mask of the given cosigner.
func (m *Mask) SetMaskBit(signer int, enable bool) error {
	if signer > len(m.publics) {
		return errors.New("index out of range")
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	if ((m.mask[byt] & msk) == 0) && enable {
		m.mask[byt] ^= msk // flip bit in mask from 0 to 1
		m.AggregatePublic.Add(m.AggregatePublic, m.publics[signer])
	}
	if ((m.mask[byt] & msk) != 0) && !enable {
		m.mask[byt] ^= msk // flip bit in mask from 1 to 0
		m.AggregatePublic.Sub(m.AggregatePublic, m.publics[signer])
	}
	return nil
}

// MaskBit returns a boolean value indicating whether the given signer is
// enabled (true) or disabled (false).
func (m *Mask) MaskBit(signer int) bool {
	if signer > len(m.publics) {
		return false // TODO: should this throw an error? It was a panic before.
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	return (m.mask[byt] & msk) != 0
}

// CountEnabled returns the number of enabled nodes in the CoSi participation
// mask, i.e., it returns the hamming weight of the mask.
func (m *Mask) CountEnabled() int {
	hw := 0
	for i := range m.publics {
		if m.MaskBit(i) {
			hw++
		}
	}
	return hw
}

// CountTotal returns the total number of nodes this CoSi instance knows.
func (m *Mask) CountTotal() int {
	return len(m.publics)
}

// AggregateMasks computes the bitwise OR of the two given participation masks.
func AggregateMasks(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("mismatching mask lengths")
	}
	m := make([]byte, len(a))
	for i := range m {
		m[i] = a[i] | b[i]
	}
	return m, nil
}

// Policy represents a fully customizable cosigning policy deciding what
// cosigner sets are and aren't sufficient for a collective signature to be
// considered acceptable to a verifier. The Check method may inspect the set of
// participants that cosigned by invoking cosi.Mask and/or cosi.MaskBit, and may
// use any other relevant contextual information (e.g., how security-critical
// the operation relying on the collective signature is) in determining whether
// the collective signature was produced by an acceptable set of cosigners.
type Policy interface {
	Check(m *Mask) bool
}

// CompletePolicy is the default policy requiring that all participants have
// cosigned to make a collective signature valid.
type CompletePolicy struct {
}

// Check verifies that all participants have contributed to a collective
// signature.
func (p CompletePolicy) Check(m *Mask) bool {
	return m.CountEnabled() == m.CountTotal()
}

// ThresholdPolicy allows to specify a simple t-of-n policy requring that at
// least the given threshold number of participants have cosigned to make a
// collective signature valid.
type ThresholdPolicy struct {
	t int
}

// Check verifies that at least a threshold number of participants have
// contributed to a collective signature.
func (p ThresholdPolicy) Check(m *Mask) bool {
	return m.CountEnabled() >= p.t
}
