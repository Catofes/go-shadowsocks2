package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

func logf(f string, v ...interface{}) {
	if config.Verbose {
		log.Printf(f, v...)
	}
}

func main() {

	var flags struct {
		Client    string
		Server    string
		Cipher    string
		Key       string
		Password  string
		Keygen    int
		Socks     string
		RedirTCP  string
		RedirTCP6 string
		TCPTun    string
		UDPTun    string
	}

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Client == "" {
		flags.Client = os.Getenv("SS_CLIENT")
	}
	if flags.Server == "" {
		flags.Server = os.Getenv("SS_SERVER")
	}
	if flags.Cipher == "" {
		flags.Cipher = os.Getenv("SS_CIPHER")
	}
	if flags.Key == "" {
		flags.Key = os.Getenv("SS_KEY")
	}
	if flags.Password == "" {
		flags.Password = os.Getenv("SS_PASSWORD")
	}
	if flags.Socks == "" {
		flags.Socks = os.Getenv("SS_SOCKS")
	}
	if flags.RedirTCP == "" {
		flags.RedirTCP = os.Getenv("SS_REDIRTCP")
	}
	if flags.RedirTCP6 == "" {
		flags.RedirTCP6 = os.Getenv("SS_REDIRTCP6")
	}
	if flags.TCPTun == "" {
		flags.TCPTun = os.Getenv("SS_TCPTUN")
	}
	if flags.UDPTun == "" {
		flags.UDPTun = os.Getenv("SS_UDPTUN")
	}

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
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

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(p[0], addr, p[1], ciph.PacketConn)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
		}

		if flags.RedirTCP != "" {
			go redirLocal(flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(flags.RedirTCP6, addr, ciph.StreamConn)
		}
	}

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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
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
