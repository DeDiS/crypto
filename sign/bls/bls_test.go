package bls

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

func TestBLS(t *testing.T) {
	suite := bn256.NewSuite()
	msg := []byte("Hello Boneh-Lynn-Shacham")
	BLSRoutine(t, msg, suite)
}

func FuzzBLS(f *testing.F) {
	suite := bn256.NewSuite()
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) < 1 || len(msg) > 1000 {
			t.Skip("msg must have byte length between 1 and 1000")
		}
		BLSRoutine(t, msg, suite)
	})
}

func BLSRoutine(t *testing.T, msg []byte, suite *bn256.Suite) {
	scheme := NewSchemeOnG1(suite)
	private, public := scheme.NewKeyPair(blake2xb.New(msg))
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	err = scheme.Verify(public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, public := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	sig, err := scheme.Sign(private, msg)
	require.Nil(t, err)
	_, public := scheme.NewKeyPair(random.New())
	if scheme.Verify(public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSAggregateSignatures(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
	require.Nil(t, err)

	aggregatedKey := scheme.AggregatePublicKeys(public1, public2)

	err = scheme.Verify(aggregatedKey, msg, aggregatedSig)
	require.Nil(t, err)
}

func TestBLSFailAggregatedSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
	require.Nil(t, err)
	aggregatedKey := scheme.AggregatePublicKeys(public1, public2)

	aggregatedSig[0] ^= 0x01
	if scheme.Verify(aggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
func TestBLSFailAggregatedKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	_, public3 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(t, err)
	aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
	require.Nil(t, err)
	badAggregatedKey := scheme.AggregatePublicKeys(public1, public2, public3)

	if scheme.Verify(badAggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}
func TestBLSBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg1)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg2)
	require.Nil(t, err)
	aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
	require.Nil(t, err)

	err = BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig)
	require.Nil(t, err)
}
func TestBLSFailBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	sig1, err := scheme.Sign(private1, msg1)
	require.Nil(t, err)
	sig2, err := scheme.Sign(private2, msg2)
	require.Nil(t, err)

	t.Run("fails with a bad signature", func(t *testing.T) {
		aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2)
		require.Nil(t, err)
		msg2[0] ^= 0x01
		if BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

	t.Run("fails with a duplicate msg", func(t *testing.T) {
		private3, public3 := scheme.NewKeyPair(random.New())
		sig3, err := scheme.Sign(private3, msg1)
		require.Nil(t, err)
		aggregatedSig, err := scheme.AggregateSignatures(sig1, sig2, sig3)
		require.Nil(t, err)

		if BatchVerify(suite, []kyber.Point{public1, public2, public3}, [][]byte{msg1, msg2, msg1}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	BenchCreateKeys(b, scheme, 1)
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	BenchSign(b, scheme, msg, []kyber.Scalar{private})
}

func BenchmarkBLSAggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, _ := scheme.NewKeyPair(random.New())
	private2, _ := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.AggregateSignatures(sig1, sig2)
	}
}

func BenchmarkBLSVerifyAggregate(b *testing.B) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)
	private1, public1 := scheme.NewKeyPair(random.New())
	private2, public2 := scheme.NewKeyPair(random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := scheme.Sign(private1, msg)
	require.Nil(b, err)
	sig2, err := scheme.Sign(private2, msg)
	require.Nil(b, err)
	sig, err := scheme.AggregateSignatures(sig1, sig2)
	key := scheme.AggregatePublicKeys(public1, public2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheme.Verify(key, msg, sig)
	}
}

func BenchmarkBLSVerifyBatchVerify(b *testing.B) {
	suite, scheme, publics, _, msgs, sigs := PrepareBLS(100)
	BenchVerify(b, sigs, scheme, suite, publics, msgs)
}

func TestBinaryMarshalAfterAggregation_issue400(t *testing.T) {
	suite := bn256.NewSuite()
	scheme := NewSchemeOnG1(suite)

	_, public1 := scheme.NewKeyPair(random.New())
	_, public2 := scheme.NewKeyPair(random.New())

	workingKey := scheme.AggregatePublicKeys(public1, public2, public1)

	workingBits, err := workingKey.MarshalBinary()
	require.Nil(t, err)

	workingPoint := suite.G2().Point()
	err = workingPoint.UnmarshalBinary(workingBits)
	require.Nil(t, err)

	// this was failing before the fix
	aggregatedKey := scheme.AggregatePublicKeys(public1, public1, public2)

	bits, err := aggregatedKey.MarshalBinary()
	require.Nil(t, err)

	point := suite.G2().Point()
	err = point.UnmarshalBinary(bits)
	require.Nil(t, err)
}
