// Package vss implements the verifiable secret sharing scheme from the
// paper "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold
// Scheme for Implicit Certificates".
// VSS enables a dealer to share a secret securely and verifiably among n
// participants out of which at least t are required for its reconstruction.
// The verifiability of the process prevents a
// malicious dealer from influencing the outcome to his advantage as each
// verifier can check the validity of the received share. The protocol has the
// following steps:
//
//   1) The dealer send a Deal to every verifiers using `Deals()`. Each deal must
//   be sent securely to one verifier whose public key is at the same index than
//   the index of the Deal.
//
//   2) Each verifier processes the Deal with `ProcessDeal`.
//   This function returns a Response which can be twofold:
//   - an approval, to confirm a correct deal
//   - a complaint to announce an incorrect deal notifying others that the
//     dealer might be malicious.
//	 All Responses must be broadcasted to every verifiers and the dealer.
//   3) The dealer can respond to each complaint by a justification revealing the
//   share he originally sent out to the accusing verifier. This is done by
//   calling `ProcessResponse` on the `Dealer`.
//   4) The verifiers refuse the shared secret and abort the protocol if there
//   are at least t complaints OR if a Justification is wrong. The verifiers
//   accept the shared secret if there are at least t approvals at which point
//   any t out of n verifiers can reveal their shares to reconstruct the shared
//   secret.
package vss

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/crypto.v0/sign"
)

// Dealer encapsulates for creating and distributing the shares and for
// replying to any Responses.
type Dealer struct {
	suite  abstract.Suite
	reader cipher.Stream
	// long is the longterm key of the Dealer
	long          abstract.Scalar
	pub           abstract.Point
	secret        abstract.Scalar
	secretCommits []abstract.Point
	verifiers     []abstract.Point
	hkdfContext   []byte
	// threshold of shares that is needed to reconstruct the secret
	t int
	// sessionID is a unique identifier for the whole session of the scheme
	sessionID []byte
	// list of deals this Dealer has generated
	deals []*Deal
	*aggregator
}

// Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
type Deal struct {
	// Unique session identifier for this protocol run
	SessionID []byte
	// Private share generated by the dealer
	SecShare *share.PriShare
	// Random share generated by the dealer
	RndShare *share.PriShare
	// Threshold used for this secret sharing run
	T uint32
	// Commitments are the coefficients used to verify the shares against
	Commitments []abstract.Point
}

// EncryptedDeal contains the deal in a encrypted form only decipherable by the
// correct recipient. The encryption is performed in a similar manner as what is
// done in TLS. The dealer generates a temporary key pair, signs it with its
// longterm secret key.
type EncryptedDeal struct {
	// Ephemeral Diffie Hellman key
	DHKey abstract.Point
	// Signature of the DH key by the longterm key of the dealer
	Signature []byte
	// Nonce used for the encryption
	Nonce []byte
	// AEAD encryption of the deal marshalled by protobuf
	Cipher []byte
}

// Response is sent by the verifiers to all participants and holds each
// individual validation or refusal of a Deal.
type Response struct {
	// SessionID related to this run of the protocol
	SessionID []byte
	// Index of the verifier issuing this Response
	Index uint32
	// Approved is true if the Response is valid
	Approved bool
	// Signature over the whole packet
	Signature []byte
}

// Justification is a message that is broadcasted by the Dealer in response to
// a Complaint. It contains the original Complaint as well as the shares
// distributed to the complainer.
type Justification struct {
	// SessionID related to the current run of the protocol
	SessionID []byte
	// Index of the verifier who issued the Complaint,i.e. index of this Deal
	Index uint32
	// Deal in cleartext
	Deal *Deal
	// Signature over the whole packet
	Signature []byte
}

// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
// does not have to be trusted by other Verifiers. The security parameter t is
// the number of shares required to reconstruct the secret. It is HIGHLY
// RECOMMENDED to use a threshold higher or equal than what the method
// MinimumT() returns, otherwise it breaks the security assumptions of the whole
// scheme. It returns an error if the t is inferior or equal to 2.
func NewDealer(suite abstract.Suite, longterm, secret abstract.Scalar, verifiers []abstract.Point, r cipher.Stream, t int) (*Dealer, error) {
	d := &Dealer{
		suite:     suite,
		long:      longterm,
		secret:    secret,
		verifiers: verifiers,
	}
	if !validT(t, verifiers) {
		return nil, fmt.Errorf("dealer: t %d invalid", t)
	}
	d.t = t

	H := deriveH(d.suite, d.verifiers)
	f := share.NewPriPoly(d.suite, d.t, d.secret, r)
	g := share.NewPriPoly(d.suite, d.t, nil, r)
	d.pub = d.suite.Point().Mul(nil, d.long)

	// Compute public polynomial coefficients
	F := f.Commit(d.suite.Point().Base())
	_, d.secretCommits = F.Info()
	G := g.Commit(H)

	C, err := F.Add(G)
	if err != nil {
		return nil, err
	}
	_, commitments := C.Info()

	d.sessionID, err = sessionID(d.suite, d.pub, d.verifiers, commitments, d.t)
	if err != nil {
		return nil, err
	}

	d.aggregator = newAggregator(d.suite, d.pub, d.verifiers, commitments, d.t, d.sessionID)
	// C = F + G
	d.deals = make([]*Deal, len(d.verifiers))
	for i := range d.verifiers {
		fi := f.Eval(i)
		gi := g.Eval(i)
		d.deals[i] = &Deal{
			SessionID:   d.sessionID,
			SecShare:    fi,
			RndShare:    gi,
			Commitments: commitments,
			T:           uint32(d.t),
		}
	}
	d.hkdfContext = context(suite, d.pub, verifiers)
	return d, nil
}

// PlaintextDeal ...
func (d *Dealer) PlaintextDeal(i int) (*Deal, error) {
	if i >= len(d.deals) {
		return nil, errors.New("dealer: PlaintextDeal given wrong index")
	}
	return d.deals[i], nil
}

// EncryptedDeal returns the encryption of the deal that must be given to the
// verifier at index i.
// The dealer first generates a temporary Diffie Hellman key, signs it using its
// longterm key, and computes the shared key depending on its longterm and
// ephemeral key and the verifier's public key.
// This shared key is then fed into a HKDF whose output is the key to a AEAD
// (AES256-GCM) scheme to encrypt the deal.
func (d *Dealer) EncryptedDeal(i int) (*EncryptedDeal, error) {
	vPub, ok := findPub(d.verifiers, uint32(i))
	if !ok {
		return nil, errors.New("dealer: wrong index to generate encrypted deal")
	}
	// gen ephemeral key
	dhSecret := d.suite.Scalar().Pick(random.Stream)
	dhPublic := d.suite.Point().Mul(nil, dhSecret)
	// signs the public key
	dhPublicBuff, _ := dhPublic.MarshalBinary()
	signature, err := sign.Schnorr(d.suite, d.long, dhPublicBuff)
	if err != nil {
		return nil, err
	}
	// AES128-GCM
	pre := dhExchange(d.suite, dhSecret, vPub)
	gcm, err := newAEAD(d.suite.Hash, pre, d.hkdfContext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	dealBuff, err := d.deals[i].MarshalBinary()
	if err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nil, nonce, dealBuff, d.hkdfContext)
	return &EncryptedDeal{
		DHKey:     dhPublic,
		Signature: signature,
		Nonce:     nonce,
		Cipher:    encrypted,
	}, nil
}

// EncryptedDeals calls `EncryptedDeal` for each index of the verifier and
// returns the list of encrypted deals. Each index in the returned slice
// corresponds to the index in the list of verifiers.
func (d *Dealer) EncryptedDeals() ([]*EncryptedDeal, error) {
	deals := make([]*EncryptedDeal, len(d.verifiers))
	var err error
	for i := range d.verifiers {
		deals[i], err = d.EncryptedDeal(i)
		if err != nil {
			return nil, err
		}
	}
	return deals, nil
}

// ProcessResponse analyzes the given Response. If it's a valid complaint, then
// it returns a Justification. This Justification must be broadcasted to every
// participants. If it's an invalid complaint, it returns an error about the
// complaint. The verifiers will also ignore an invalid Complaint.
func (d *Dealer) ProcessResponse(r *Response) (*Justification, error) {
	if err := d.verifyResponse(r); err != nil {
		return nil, err
	}
	if r.Approved {
		return nil, nil
	}

	j := &Justification{
		SessionID: d.sessionID,
		// index is guaranteed to be good because of d.verifyResponse before
		Index: r.Index,
		Deal:  d.deals[int(r.Index)],
	}
	sig, err := sign.Schnorr(d.suite, d.long, j.Hash(d.suite))
	if err != nil {
		return nil, err
	}
	j.Signature = sig
	return j, nil
}

// SecretCommit returns the commitment of the secret being shared by this
// dealer. This function is only to be called once the deal has enough approvals
// and is verified otherwise it returns nil.
func (d *Dealer) SecretCommit() abstract.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.suite.Point().Mul(nil, d.secret)
}

// Commits returns the commitments of the coefficient of the secret polynomial
// the Dealer is sharing.
func (d *Dealer) Commits() []abstract.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.secretCommits
}

// Key returns the longterm key pair used by this Dealer.
func (d *Dealer) Key() (abstract.Scalar, abstract.Point) {
	return d.long, d.pub
}

// SessionID returns the current sessionID generated by this dealer for this
// protocol run.
func (d *Dealer) SessionID() []byte {
	return d.sessionID
}

// Verifier receives a Deal from a Dealer, can reply with a Complaint, and can
// collaborate with other Verifiers to reconstruct a secret.
type Verifier struct {
	suite       abstract.Suite
	longterm    abstract.Scalar
	pub         abstract.Point
	dealer      abstract.Point
	index       int
	verifiers   []abstract.Point
	hkdfContext []byte
	*aggregator
}

// NewVerifier returns a Verifier out of:
// - its longterm secret key
// - the longterm dealer public key
// - the list of public key of verifiers. The list MUST include the public key
// of this Verifier also.
// The security parameter t of the secret sharing scheme is automatically set to
// a default safe value. If a different t value is required, it is possible to set
// it with `verifier.SetT()`.
func NewVerifier(suite abstract.Suite, longterm abstract.Scalar, dealerKey abstract.Point,
	verifiers []abstract.Point) (*Verifier, error) {

	pub := suite.Point().Mul(nil, longterm)
	var ok bool
	var index int
	for i, v := range verifiers {
		if v.Equal(pub) {
			ok = true
			index = i
			break
		}
	}
	if !ok {
		return nil, errors.New("vss: public key not found in the list of verifiers")
	}
	v := &Verifier{
		suite:       suite,
		longterm:    longterm,
		dealer:      dealerKey,
		verifiers:   verifiers,
		pub:         pub,
		index:       index,
		hkdfContext: context(suite, dealerKey, verifiers),
	}
	return v, nil
}

// ProcessEncryptedDeal decrypt the deal received from the Dealer.
// If the deal is valid, i.e. the verifier can verify its shares
// against the public coefficients and the signature is valid, an approval
// response is returned and must be broadcasted to every participants
// including the dealer.
// If the deal itself is invalid, it returns a complaint response that must be
// broadcasted to every other participants including the dealer.
// If the deal has already been received, or the signature generation of the
// response failed, it returns an error without any responses.
func (v *Verifier) ProcessEncryptedDeal(e *EncryptedDeal) (*Response, error) {
	d, err := v.decryptDeal(e)
	if err != nil {
		return nil, err
	}
	if d.SecShare.I != v.index {
		return nil, errors.New("vss: verifier got wrong index from deal")
	}

	t := int(d.T)

	sid, err := sessionID(v.suite, v.dealer, v.verifiers, d.Commitments, t)
	if err != nil {
		return nil, err
	}

	if v.aggregator == nil {
		v.aggregator = newAggregator(v.suite, v.dealer, v.verifiers, d.Commitments, t, d.SessionID)
	}

	r := &Response{
		SessionID: sid,
		Index:     uint32(v.index),
		Approved:  true,
	}
	if err = v.VerifyDeal(d, true); err != nil {
		r.Approved = false
	}

	if err == errDealAlreadyProcessed {
		return nil, err
	}

	if r.Signature, err = sign.Schnorr(v.suite, v.longterm, r.Hash(v.suite)); err != nil {
		return nil, err
	}

	if err = v.aggregator.addResponse(r); err != nil {
		return nil, err
	}
	return r, nil
}

func (v *Verifier) decryptDeal(e *EncryptedDeal) (*Deal, error) {
	ephBuff, err := e.DHKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// verify signature
	if err := sign.VerifySchnorr(v.suite, v.dealer, ephBuff, e.Signature); err != nil {
		return nil, err
	}

	// compute shared key and AES526-GCM cipher
	pre := dhExchange(v.suite, v.longterm, e.DHKey)
	gcm, err := newAEAD(v.suite.Hash, pre, v.hkdfContext)
	if err != nil {
		return nil, err
	}
	decrypted, err := gcm.Open(nil, e.Nonce, e.Cipher, v.hkdfContext)
	if err != nil {
		return nil, err
	}
	deal := &Deal{}
	err = deal.UnmarshalBinary(v.suite, decrypted)
	return deal, err
}

// ProcessResponse analyzes the given response. If it's a valid complaint, the
// verifier should expect to see a Justification from the Dealer. It returns an
// error if it's not a valid response.
// Call `v.DealCertified()` to check if the whole protocol is finished.
func (v *Verifier) ProcessResponse(resp *Response) error {
	return v.aggregator.verifyResponse(resp)
}

// Deal returns the Deal that this verifier has received. It returns
// nil if the deal is not certified or there is not enough approvals.
func (v *Verifier) Deal() *Deal {
	if !v.EnoughApprovals() || !v.DealCertified() {
		return nil
	}
	return v.deal
}

// ProcessJustification takes a DealerResponse and returns an error if
// something went wrong during the verification. If it is the case, that
// probably means the Dealer is acting maliciously. In order to be sure, call
// `v.EnoughApprovals()` and if true, `v.DealCertified()`.
func (v *Verifier) ProcessJustification(dr *Justification) error {
	return v.aggregator.verifyJustification(dr)
}

// Key returns the longterm key pair this verifier is using during this protocol
// run.
func (v *Verifier) Key() (abstract.Scalar, abstract.Point) {
	return v.longterm, v.pub
}

// Index returns the index of the verifier in the list of participants used
// during this run of the protocol.
func (v *Verifier) Index() int {
	return v.index
}

// SessionID returns the session id generated by the Dealer. WARNING: it returns
// an nil slice if the verifier has not received the Deal yet !
func (v *Verifier) SessionID() []byte {
	return v.sid
}

// RecoverSecret recovers the secret shared by a Dealer by gathering at least t
// Deals from the verifiers. It returns an error if there is not enough Deals or
// if all Deals don't have the same SessionID.
func RecoverSecret(suite abstract.Suite, deals []*Deal, n, t int) (abstract.Scalar, error) {
	shares := make([]*share.PriShare, len(deals))
	for i, deal := range deals {
		// all sids the same
		if bytes.Equal(deal.SessionID, deals[0].SessionID) {
			shares[i] = deal.SecShare
		} else {
			return nil, errors.New("vss: all deals need to have same session id")
		}
	}
	return share.RecoverSecret(suite, shares, t, n)
}

// aggregator is used to collect all deals, and responses for one protocol run.
// It brings common functionalities for both Dealer and Verifier structs.
type aggregator struct {
	suite     abstract.Suite
	dealer    abstract.Point
	verifiers []abstract.Point
	commits   []abstract.Point

	responses map[uint32]*Response
	sid       []byte
	deal      *Deal
	t         int
	badDealer bool
}

func newAggregator(suite abstract.Suite, dealer abstract.Point, verifiers, commitments []abstract.Point, t int, sid []byte) *aggregator {
	agg := &aggregator{
		suite:     suite,
		dealer:    dealer,
		verifiers: verifiers,
		commits:   commitments,
		t:         t,
		sid:       sid,
		responses: make(map[uint32]*Response),
	}
	return agg
}

var errDealAlreadyProcessed = errors.New("vss: verifier already received a deal")

// VerifyDeal analyzes the deal and returns an error if it's incorrect. If
// inclusion is true, it also returns an error if it the second time this struct
// analyzes a Deal.
func (a *aggregator) VerifyDeal(d *Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return errDealAlreadyProcessed

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
	}

	if !validT(int(d.T), a.verifiers) {
		return errors.New("vss: invalid t received in Deal")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("vss: find different sessionIDs from Deal")
	}

	fi := d.SecShare
	gi := d.RndShare
	if fi.I != gi.I {
		return errors.New("vss: not the same index for f and g share in Deal")
	}
	if fi.I < 0 || fi.I >= len(a.verifiers) {
		return errors.New("vss: index out of bounds in Deal")
	}
	// compute fi * G + gi * H
	fig := a.suite.Point().Base().Mul(nil, fi.V)
	H := deriveH(a.suite, a.verifiers)
	gih := a.suite.Point().Mul(H, gi.V)
	ci := a.suite.Point().Add(fig, gih)

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !ci.Equal(pubShare.V) {
		return errors.New("vss: share does not verify against commitments in Deal")
	}
	return nil
}

func (a *aggregator) verifyResponse(r *Response) error {
	if !bytes.Equal(r.SessionID, a.sid) {
		return errors.New("vss: receiving inconsistent sessionID in response")
	}

	pub, ok := findPub(a.verifiers, r.Index)
	if !ok {
		return errors.New("vss: index out of bounds in response")
	}

	if err := sign.VerifySchnorr(a.suite, pub, r.Hash(a.suite), r.Signature); err != nil {
		return err
	}

	return a.addResponse(r)
}

func (a *aggregator) verifyJustification(j *Justification) error {
	if _, ok := findPub(a.verifiers, j.Index); !ok {
		return errors.New("vss: index out of bounds in justification")
	}
	r, ok := a.responses[j.Index]
	if !ok {
		return errors.New("vss: no complaints received for this justification")
	}
	if r.Approved {
		return errors.New("vss: justification received for an approval")
	}

	if err := a.VerifyDeal(j.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		a.badDealer = true
		return err
	}
	r.Approved = true
	return nil
}

func (a *aggregator) addResponse(r *Response) error {
	if _, ok := findPub(a.verifiers, r.Index); !ok {
		return errors.New("vss: index out of bounds in Complaint")
	}
	if _, ok := a.responses[r.Index]; ok {
		return errors.New("vss: already existing response from same origin")
	}
	a.responses[r.Index] = r
	return nil
}

// EnoughApprovals returns true if enough verifiers have sent their approval for
// the deal they received.
func (a *aggregator) EnoughApprovals() bool {
	var app int
	for _, r := range a.responses {
		if r.Approved {
			app++
		}
	}
	return app >= a.t
}

// DealCertified returns true if there has been less than t complaints, all
// Justifications were correct and if EnoughApprovals() returns true.
func (a *aggregator) DealCertified() bool {
	if a == nil{
		return false
	}
	var comps int
	for _, r := range a.responses {
		if !r.Approved {
			comps++
		}
	}
	tooMuchComplaints := comps >= a.t || a.badDealer
	return a.EnoughApprovals() && !tooMuchComplaints
}

// MinimumT returns the minimum safe T that is proven to be secure with this
// protocol. It expects n, the total number of participants.
// WARNING: Setting a lower T could make
// the whole protocol insecure. Setting a higher T only makes it harder to
// reconstruct the secret.
func MinimumT(n int) int {
	return (n + 1) / 2
}

func validT(t int, verifiers []abstract.Point) bool {
	return t >= 2 && t <= len(verifiers) && int(uint32(t)) == t
}

func deriveH(suite abstract.Suite, verifiers []abstract.Point) abstract.Point {
	var b bytes.Buffer
	for _, v := range verifiers {
		v.MarshalTo(&b)
	}
	h := suite.Hash()
	h.Write(b.Bytes())
	digest := h.Sum(nil)
	base, _ := suite.Point().Pick(nil, suite.Cipher(digest))
	return base
}

func findPub(verifiers []abstract.Point, idx uint32) (abstract.Point, bool) {
	iidx := int(idx)
	if iidx >= len(verifiers) {
		return nil, false
	}
	return verifiers[iidx], true
}

func sessionID(suite abstract.Suite, dealer abstract.Point, verifiers, commitments []abstract.Point, t int) ([]byte, error) {
	h := suite.Hash()
	dealer.MarshalTo(h)

	for _, v := range verifiers {
		v.MarshalTo(h)
	}

	for _, c := range commitments {
		c.MarshalTo(h)
	}
	binary.Write(h, binary.LittleEndian, uint32(t))

	return h.Sum(nil), nil
}

// Hash returns the Hash representation of the Response
func (r *Response) Hash(s abstract.Suite) []byte {
	h := s.Hash()
	h.Write([]byte("response"))
	h.Write(r.SessionID)
	binary.Write(h, binary.LittleEndian, r.Index)
	binary.Write(h, binary.LittleEndian, r.Approved)
	return h.Sum(nil)
}

// MarshalBinary returns the binary representations of a Deal.
// The encryption of a deal operates on this binary representation.
func (d *Deal) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(d)
}

// UnmarshalBinary reads the Deal from the binary represenstation.
func (d *Deal) UnmarshalBinary(s abstract.Suite, buff []byte) error {
	constructors := make(protobuf.Constructors)
	var point abstract.Point
	var secret abstract.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return s.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return s.Scalar() }
	return protobuf.DecodeWithConstructors(buff, d, constructors)
}

// Hash returns the hash of a Justification.
func (j *Justification) Hash(s abstract.Suite) []byte {
	h := s.Hash()
	h.Write([]byte("justification"))
	h.Write(j.SessionID)
	binary.Write(h, binary.LittleEndian, j.Index)
	buff, _ := j.Deal.MarshalBinary()
	h.Write(buff)
	return h.Sum(nil)
}
