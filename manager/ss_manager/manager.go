package ss_manager

import (
	"net/url"
)

type SSManager struct {
	Port int
	Url  string
}

func (s *SSManager) Init(Url string) *SSManager {
	addr, cipher, password, err := parseURL(Url)
	if err != nil {
	}
}

type AllManager struct {
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func test() {
	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		go udpRemote(addr, ciph.PacketConn)
		go tcpRemote(addr, ciph.StreamConn)
	}
}
