package ecies

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/group/p256"
	"go.dedis.ch/kyber/v4/group/var_ed25519"
	"go.dedis.ch/kyber/v4/util/random"
)

func TestECIES(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, suite.Hash)
	require.Nil(t, err)
	plaintext, err := Decrypt(suite, private, ciphertext, suite.Hash)
	require.Nil(t, err)
	require.Equal(t, message, plaintext)
}

func TestECIESFailPoint(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	ciphertext[0] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}

func TestECIESFailCiphertext(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	l := suite.PointLen()
	ciphertext[l] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}

func BenchmarkECIES(b *testing.B) {
	suites := []struct {
		kyber.Group
	}{
		{edwards25519.NewBlakeSHA256Ed25519()},
		{var_ed25519.NewBlakeSHA256Ed25519(false)},
		{var_ed25519.NewBlakeSHA256Ed25519(true)},
		{p256.NewBlakeSHA256P256()},
		{p256.NewBlakeSHA256QR512()},
	}

	message := make([]byte, 100_000)
	_, _ = rand.Read(message)
	rand := random.New()

	for _, suite := range suites {
		private := suite.Scalar().Pick(rand)
		public := suite.Point().Mul(private, nil)

		var ct []byte
		b.Run("Encrypt/"+suite.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ct, _ = Encrypt(suite, public, message, nil)
			}
		})

		b.Run("Decrypt/"+suite.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Decrypt(suite, private, ct, nil)
			}
		})
	}
}
