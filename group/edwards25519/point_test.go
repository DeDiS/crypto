package edwards25519

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoint_Marshal(t *testing.T) {
	p := point{}
	require.Equal(t, "ed.point", fmt.Sprintf("%s", p.MarshalID()))
}

// TestPoint_HasSmallOrder ensures weakKeys are considered to have
// a small order
func TestPoint_HasSmallOrder(t *testing.T) {
	for _, key := range weakKeys {
		p := point{}
		err := p.UnmarshalBinary(key)
		require.Nil(t, err)
		require.True(t, p.HasSmallOrder(), fmt.Sprintf("%s should be considered to have a small order", hex.EncodeToString(key)))
	}
}

// Test_PointIsCanonical ensures that elements >= p are considered
// non canonical
func Test_PointIsCanonical(t *testing.T) {

	// buffer stores the candidate points (in little endian) that we'll test
	// against, starting with `prime`
	buffer := prime.Bytes()
	for i, j := 0, len(buffer)-1; i < j; i, j = i+1, j-1 {
		buffer[i], buffer[j] = buffer[j], buffer[i]
	}

	// Iterate over the 19*2 finite field elements
	point := point{}
	actualNonCanonicalCount := 0
	expectedNonCanonicalCount := 24
	for i := 0; i < 19; i++ {
		buffer[0] = byte(237 + i)
		buffer[31] = byte(127)

		// Check if it's a valid point on the curve that's
		// not canonical
		err := point.UnmarshalBinary(buffer)
		if err == nil && !point.IsCanonical(buffer) {
			actualNonCanonicalCount++
		}

		// flip bit
		buffer[31] |= 128

		// Check if it's a valid point on the curve that's
		// not canonical
		err = point.UnmarshalBinary(buffer)
		if err == nil && !point.IsCanonical(buffer) {
			actualNonCanonicalCount++
		}
	}
	require.Equal(t, expectedNonCanonicalCount, actualNonCanonicalCount, "Incorrect number of non canonical points detected")
}

// Test vectors from: https://datatracker.ietf.org/doc/rfc9380
func Test_ExpandMessageXMDSHA256(t *testing.T) {
	dst := "QUUX-V01-CS02-with-expander-SHA256-128"
	inputs := []string{
		"",
		"abc",
		"abcdef0123456789",
		"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqq",
		"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	outputLength := []int{32, 128}

	expectedHex32byte := []string{
		"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
		"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
		"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
		"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
		"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
	}

	expectedHex128byte := []string{
		"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
		"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
		"ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
		"80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
		"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487",
	}

	h := sha256.New()

	// Short
	for i := 0; i < len(inputs); i++ {
		res, err := expandMessageXMD(h, []byte(inputs[i]), dst, outputLength[0])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex32byte[i], resHex)
	}

	// Long
	for i := 0; i < len(inputs); i++ {
		res, err := expandMessageXMD(h, []byte(inputs[i]), dst, outputLength[1])
		resHex := hex.EncodeToString(res)

		assert.NoError(t, err)
		assert.Equal(t, expectedHex128byte[i], resHex)
	}
}
