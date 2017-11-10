package onet

import (
	"errors"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"net"

	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

type simulationCreate func(string) (Simulation, error)

var simulationRegistered map[string]simulationCreate

// SimulationFileName is the name of the (binary encoded) file containing the
// simulation config.
const SimulationFileName = "simulation.bin"

// Simulation is an interface needed by every protocol that wants to be available
// to be used in a simulation.
type Simulation interface {
	// This has to initialise all necessary files and copy them to the
	// 'dir'-directory. This directory will be accessible to all simulated
	// hosts.
	// Setup also gets a slice of all available hosts. In turn it has
	// to return a tree using one or more of these hosts. It can create
	// the Roster as desired, putting more than one ServerIdentity/Host on the same host.
	// The 'config'-argument holds all arguments read from the runfile in
	// toml-format.
	Setup(dir string, hosts []string) (*SimulationConfig, error)

	// Node will be run for every node and might be used to setup load-
	// creation. It is started once the Host is set up and running, but before
	// 'Run'
	Node(config *SimulationConfig) error

	// Run will begin with the simulation or return an error. It is sure
	// to be run on the host where 'tree.Root' is. It should only return
	// when all rounds are done.
	Run(config *SimulationConfig) error
}

// SimulationConfig has to be returned from 'Setup' and will be passed to
// 'Run'.
type SimulationConfig struct {
	// Represents the tree that has to be used
	Tree *Tree
	// The Roster used by the tree
	Roster *Roster
	// All private keys generated by 'Setup', indexed by the complete addresses
	PrivateKeys map[network.Address]kyber.Scalar
	// If non-nil, points to our overlay
	Overlay *Overlay
	// If non-nil, points to our host
	Server *Server
	// Additional configuration used to run
	Config string
}

// SimulationConfigFile stores the state of the simulation's config.
// Only used internally.
type SimulationConfigFile struct {
	TreeMarshal *TreeMarshal
	Roster      *Roster
	PrivateKeys map[network.Address]kyber.Scalar
	Config      string
}

// LoadSimulationConfig gets all configuration from dir + SimulationFileName and instantiates the
// corresponding host 'ca'.
func LoadSimulationConfig(dir, ca string, s network.Suite) ([]*SimulationConfig, error) {
	network.RegisterMessage(SimulationConfigFile{})
	bin, err := ioutil.ReadFile(dir + "/" + SimulationFileName)
	if err != nil {
		return nil, err
	}
	_, msg, err := network.Unmarshal(bin, s)
	if err != nil {
		return nil, err
	}
	// Redirect all calls from context.(Save|Load) to memory.
	setContextDataPath("")
	scf := msg.(*SimulationConfigFile)
	sc := &SimulationConfig{
		Roster:      scf.Roster,
		PrivateKeys: scf.PrivateKeys,
		Config:      scf.Config,
	}
	sc.Tree, err = scf.TreeMarshal.MakeTree(s, sc.Roster)
	if err != nil {
		return nil, err
	}

	var ret []*SimulationConfig
	if ca != "" {
		if !strings.Contains(ca, ":") {
			// to correctly match hosts a column is needed, else
			// 10.255.0.1 would also match 10.255.0.10 and others
			ca += ":"
		}
		for _, e := range sc.Roster.List {
			if strings.Contains(e.Address.String(), ca) {
				server := NewServerTCP(e, scf.PrivateKeys[e.Address], s)
				scNew := *sc
				scNew.Server = server
				scNew.Overlay = server.overlay
				ret = append(ret, &scNew)
			}
		}
		if len(ret) == 0 {
			return nil, errors.New("Address not used in simulation: " + ca)
		}
	} else {
		ret = append(ret, sc)
	}
	addr := string(sc.Roster.List[0].Address)
	if strings.Contains(addr, "127.0.0.") /*|| strings.Contains(addr, "localhost") */ {
		// Now strip all superfluous numbers of localhost
		for i := range sc.Roster.List {
			_, port, _ := net.SplitHostPort(sc.Roster.List[i].Address.NetworkAddress())
			// put 127.0.0.1 because 127.0.0.X is not reachable on Mac OS X
			sc.Roster.List[i].Address = network.NewAddress(network.PlainTCP, "127.0.0.1:"+port)
		}
	}
	return ret, nil
}

// Save takes everything in the SimulationConfig structure and saves it to
// dir + SimulationFileName
func (sc *SimulationConfig) Save(dir string) error {
	network.RegisterMessage(&SimulationConfigFile{})
	scf := &SimulationConfigFile{
		TreeMarshal: sc.Tree.MakeTreeMarshal(),
		Roster:      sc.Roster,
		PrivateKeys: sc.PrivateKeys,
		Config:      sc.Config,
	}
	buf, err := network.Marshal(scf)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(dir+"/"+SimulationFileName, buf, 0660)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

// GetService returns the service with the given name.
func (sc *SimulationConfig) GetService(name string) Service {
	return sc.Server.serviceManager.service(name)
}

// SimulationRegister is must to be called to register a simulation.
// Protocol or simulation developers must not forget to call this function
// with the protocol's name.
func SimulationRegister(name string, sim simulationCreate) {
	if simulationRegistered == nil {
		simulationRegistered = make(map[string]simulationCreate)
	}
	simulationRegistered[name] = sim
}

// NewSimulation returns a simulation and decodes the 'conf' into the
// simulation-structure
func NewSimulation(name string, conf string) (Simulation, error) {
	sim, ok := simulationRegistered[name]
	if !ok {
		return nil, errors.New("Didn't find simulation " + name)
	}
	simInst, err := sim(conf)
	if err != nil {
		return nil, err
	}
	_, err = toml.Decode(conf, simInst)
	if err != nil {
		return nil, err
	}
	return simInst, nil
}

// SimulationBFTree is the main struct storing the data for all the simulations
// which use a tree with a certain branching factor or depth.
type SimulationBFTree struct {
	Rounds     int
	BF         int
	Hosts      int
	SingleHost bool
	Depth      int
	Suite      string
}

// CreateRoster creates an Roster with the host-names in 'addresses'.
// It creates 's.Hosts' entries, starting from 'port' for each round through
// 'addresses'. The network.Address(es) created are of type PlainTCP.
func (s *SimulationBFTree) CreateRoster(sc *SimulationConfig, addresses []string, port int, suite network.Suite) {
	start := time.Now()
	nbrAddr := len(addresses)
	if sc.PrivateKeys == nil {
		sc.PrivateKeys = make(map[network.Address]kyber.Scalar)
	}
	hosts := s.Hosts
	if s.SingleHost {
		// If we want to work with a single host, we only make one
		// host per server
		log.Fatal("Not supported yet")
		hosts = nbrAddr
		if hosts > s.Hosts {
			hosts = s.Hosts
		}
	}
	localhosts := false
	listeners := make([]net.Listener, hosts)
	services := make([]net.Listener, hosts)
	if /*strings.Contains(addresses[0], "localhost") || */ strings.Contains(addresses[0], "127.0.0.") {
		localhosts = true
	}
	entities := make([]*network.ServerIdentity, hosts)
	log.Lvl3("Doing", hosts, "hosts")
	key := key.NewKeyPair(suite)
	for c := 0; c < hosts; c++ {
		key.Secret.Add(key.Secret,
			key.Suite.Scalar().One())
		key.Public.Add(key.Public,
			key.Suite.Point().Base())
		address := addresses[c%nbrAddr] + ":"
		var add network.Address
		if localhosts {
			// If we have localhosts, we have to search for an empty port
			port := 0
			for port == 0 {

				var err error
				listeners[c], err = net.Listen("tcp", ":0")
				if err != nil {
					log.Fatal("Couldn't search for empty port:", err)
				}
				_, p, _ := net.SplitHostPort(listeners[c].Addr().String())
				port, _ = strconv.Atoi(p)
				services[c], err = net.Listen("tcp", ":"+strconv.Itoa(port+1))
				if err != nil {
					port = 0
				}
			}
			address += strconv.Itoa(port)
			add = network.NewTCPAddress(address)
			log.Lvl4("Found free port", address)
		} else {
			address += strconv.Itoa(port + (c/nbrAddr)*2)
			add = network.NewTCPAddress(address)
		}
		entities[c] = network.NewServerIdentity(key.Public.Clone(), add)
		sc.PrivateKeys[entities[c].Address] = key.Secret.Clone()
	}

	// And close all our listeners
	if localhosts {
		for _, l := range listeners {
			err := l.Close()
			if err != nil {
				log.Fatal("Couldn't close port:", l, err)
			}
		}
		for _, l := range services {
			err := l.Close()
			if err != nil {
				log.Fatal("Couldn't close port:", l, err)
			}
		}
	}

	sc.Roster = NewRoster(entities)
	log.Lvl3("Creating entity List took: " + time.Now().Sub(start).String())
}

// CreateTree the tree as defined in SimulationBFTree and stores the result
// in 'sc'
func (s *SimulationBFTree) CreateTree(sc *SimulationConfig) error {
	log.Lvl3("CreateTree strarted")
	start := time.Now()
	if sc.Roster == nil {
		return errors.New("Empty Roster")
	}
	sc.Tree = sc.Roster.GenerateBigNaryTree(s.GetSuite(), s.BF, s.Hosts)
	log.Lvl3("Creating tree took: " + time.Now().Sub(start).String())
	return nil
}

// Node - standard registers the entityList and the Tree with that Overlay,
// so we don't have to pass that around for the experiments.
func (s *SimulationBFTree) Node(sc *SimulationConfig) error {
	sc.Overlay.RegisterRoster(sc.Roster)
	sc.Overlay.RegisterTree(sc.Tree)
	return nil
}

func (s *SimulationBFTree) GetSuite() (ns network.Suite) {
	ns = edwards25519.NewAES128SHA256Ed25519()
	if s.Suite == "" {
		return
	}
	defer func() {
		if err := recover(); err != nil {
			return
		}
	}()
	si := group.Suite(s.Suite)
	ns = si.(network.Suite)
	return
}

// GetSingleHost returns the 'SingleHost'-flag
func (sc SimulationConfig) GetSingleHost() bool {
	var sh struct{ SingleHost bool }
	_, err := toml.Decode(sc.Config, &sh)
	if err != nil {
		log.Error("Couldn't decode string", sc.Config, "into toml.")
		return false
	}
	return sh.SingleHost
}
