//purbtls is a simple TLS like protocol for encrypted communication.
//Assumes that the client has a public key for the server at the beggining of
//the protocol.

/* Protocol overview:
* Client already has public key and suite.
* Client generates a clientHelloPurb that contains required session info:
	*
	*
	*
* Server then replies with a serverHelloPurb that contains the following:
	*
	*
	*
	* Then shared key is generated (ECDH probably)


	Can purbs be simplified, because we know the message will always be with
	one key to one recipient?
	What is lost if you do this?
	PURB for sinle recipient could just be
	[elligator key][encrypted sym key][encrypted message]
	Can we authenticate encrypted sym key?

	Ignores why the server can trust the client?


	Only need 1 round trip.
*/
package purbtls

import (
	//	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	//	"github.com/dedis/crypto/cipher/aes"
	"fmt"
	"github.com/dedis/crypto/purb"
	"github.com/dedis/crypto/random"
	"net"
	"time"
)

//How many bytes symkey+message_start is
//TODO make it easy for different entrypoint sizes.
const DATALEN = 24

//Confirmation data
const CONFDATA = "confirmation message1234"

//layout of suite entrypoints default
var KEYPOS = map[string][]int{
	edwards.NewAES128SHA256Ed25519(true).String(): {
		0 * purb.KEYLEN, 1 * purb.KEYLEN,
	},
	edwards.NewAES128SHA256Ed1174(true).String(): {
		0 * purb.KEYLEN, 1 * purb.KEYLEN, 2 * purb.KEYLEN,
	},
}

/*

//Entry holds the info required to create an entrypoint for each recipient.
//Duplicated from purbgp code, will probably not be needed.
type Entry struct {
	Suite  abstract.Suite // Ciphersuite this public key is drawn from
	PriKey abstract.Secret
	PubKey abstract.Point // Public key of this entrypoint's owner
	Data   []byte         // Entrypoint data decryptable by owner
}
*/
//Constants for suites.
//const {}
type Config struct {
	//Needed fields
	//List of public key suites to use
	//Server public key. known by client
	//Server Private key. known by server
	//holds the server keys, if it is client then only public keys will be seen
	keys      []purb.Entry
	is_client bool
	sendKey   []byte
	recvKey   []byte
}

//listener structure taken from golang tls implementation
type listener struct {
	net.Listener
	config *Config
}

//Possibly use a connection, for all functions.
type PurbConn struct {
	con net.Conn
	cf  *Config
}

//What functions will be needed
//Two phases
//Handshake
//General writing.

//listener structure taken from golang tls implementation
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

//Might have some value in making it return net.Conn, as tls go does,
//but for now going to return a PurbConn
func (l *listener) Accept() (conn net.Conn, err error) {
	con, err := l.Listener.Accept()
	if err != nil {
		return
	}

	c := Server(con, l.config)
	return c, nil
}
func Server(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
	purbs := new(PurbConn)
	//Perform handshake
	//get handshake message
	buf := make([]byte, 1024)
	for {
		l, err := c.Read(buf)

		if err != nil {
			fmt.Println(err)
		}
		if l > 0 {
			//Choose a key
			entry := conf.keys[len(conf.keys)-1]
			//		entry := conf.keys[0]
			_, val := purb.AttemptDecodeTLS(entry.Suite, entry.PriKey, KEYPOS,
				buf, random.Stream, CONFDATA)
			fmt.Println(val.String())
			fmt.Println(l, "recieved purb")
			break
		}
	}
	c.Write([]byte("test:"))
	purbs.con = c
	purbs.cf = conf

	return purbs
}
func Client(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
	purbc := new(PurbConn)
	purbc.con = c
	purbc.cf = conf
	//Set entrypoints
	for i := range conf.keys {
		e := &conf.keys[i]
		e.Data = []byte(CONFDATA)
		fmt.Println(i)
		fmt.Println(e.Suite)
		fmt.Println(e.PubKey)
		fmt.Println(e.Data)
	}
	fmt.Println(conf.keys)
	purbHeader, _ := purb.GenPurbTLS(conf.keys, KEYPOS)
	fmt.Println(conf.keys)
	c.Write(purbHeader)
	buf := make([]byte, 1024)
	for {
		l, err := c.Read(buf)
		if err != nil {
			fmt.Println(err)
		}

		if l > 0 {
			//Decrypt using shared keys from conf.keys (populated by GenPurbTLS)
			fmt.Println(string(buf))
			break
		}
	}
	return purbc

}

//Terminology for functions is from tls go implementation.
//Listen for the server. Creates a connection and listens.Config
//Probably Listen(network, laddr string, cnf *Config);

//For client a dial(conn net.conn, cnf *Config)

//General use is set up Config, then call either Dial(), or Listen(),

func Listen(network, address string, conf *Config) (net.Listener, error) {

	listen, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return NewListener(listen, conf), nil
}

//Dial creates a connection to a server using purbtls negotiation.
//Returns err
func Dial(network, address string, conf *Config) (*PurbConn, error) {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return nil, err
	}

	c := Client(conn, conf)
	return c, nil

}

func (conn *PurbConn) Write(data []byte) (int, error) {
	return conn.con.Write(data)
}

func (conn *PurbConn) Read(data []byte) (int, error) {
	i, err := conn.con.Read(data)
	return i, err

}
func (conn *PurbConn) Close() error {
	return conn.con.Close()
}
func (conn *PurbConn) LocalAddr() net.Addr {
	return conn.con.LocalAddr()
}
func (conn *PurbConn) RemoteAddr() net.Addr {
	return conn.con.RemoteAddr()
}
func (conn *PurbConn) SetDeadline(t time.Time) error {
	return conn.con.SetDeadline(t)
}
func (conn *PurbConn) SetReadDeadline(t time.Time) error {
	return conn.con.SetReadDeadline(t)
}
func (conn *PurbConn) SetWriteDeadline(t time.Time) error {
	return conn.con.SetWriteDeadline(t)
}
