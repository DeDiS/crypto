package protobuf

import (
	"reflect"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/openssl"
)

type TestEncoding struct {
	S abstract.Secret
	P abstract.Point
}

func (t *TestEncoding) Equal(t2 *TestEncoding) bool {
	return t.S.Equal(t2.S) && t.P.Equal(t2.P)
}

var aSecret abstract.Secret
var tSecret = reflect.TypeOf(&aSecret).Elem()

var aPoint abstract.Point
var tPoint = reflect.TypeOf(&aPoint).Elem()

func testEncoding(t *testing.T, suite abstract.Suite) {
	cons := Constructors{
		tSecret: func() interface{} { return suite.Secret() },
		tPoint:  func() interface{} { return suite.Point() },
	}
	s := suite.Secret().One()
	p := suite.Point().Mul(nil, s)

	test := TestEncoding{s, p}
	buf := Encode(&test)

	test2 := TestEncoding{}
	err := Decode(buf, &test2, cons)
	if err != nil || !test.Equal(&test2) {
		t.Error(err)
	}
}

func TestEncodingInterface(t *testing.T) {
	testEncoding(t, nist.NewAES128SHA256P256())
	testEncoding(t, nist.NewAES128SHA256QR512())
	testEncoding(t, openssl.NewAES128SHA256P256())
	testEncoding(t, edwards.NewAES128SHA256Ed25519(false))
}
