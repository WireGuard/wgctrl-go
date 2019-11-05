package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/alecthomas/kingpin"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	rootCmd := newCommandLine()
	getCmd, getOpt := newGetCommand(rootCmd)
	setCmd, setOpt := newSetCommand(rootCmd)
	switch kingpin.MustParse(rootCmd.Parse(os.Args[1:])) {
	case getCmd.FullCommand():
		getConfig(*getOpt)
	case setCmd.FullCommand():
		setConfig(*setOpt)
	}
}

func newCommandLine() *kingpin.Application {
	return kingpin.New("wgconf", "wireguard configuring tool")
}

type getOption struct {
	Interface      string
	ShowCredential bool
}

type setOption struct {
	Interface string
	Config    string
}

func newGetCommand(root *kingpin.Application) (*kingpin.CmdClause, *getOption) {
	opt := getOption{}
	cmd := root.Command("get", "get wireguard configuration")
	cmd.Flag("interface", "interface to show").StringVar(&opt.Interface)
	cmd.Flag("show-credential", "show credentials for interface").BoolVar(&opt.ShowCredential)
	return cmd, &opt
}

func newSetCommand(root *kingpin.Application) (*kingpin.CmdClause, *setOption) {
	opt := setOption{}
	cmd := root.Command("set", "set wireguard configuration")
	cmd.Flag("interface", "interface to set").StringVar(&opt.Interface)
	cmd.Flag("config", "configuration file").StringVar(&opt.Config)
	return cmd, &opt
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func getConfig(opt getOption) {

	client, err := wgctrl.New()
	checkError(err)
	dev, err := client.Device(opt.Interface)
	checkError(err)
	fmt.Printf("Interface: %s (%s)\n", opt.Interface, dev.Type.String())
	fmt.Printf("  public key: %s\n", dev.PublicKey.String())
	privkeyStr := "(hidden)"
	if opt.ShowCredential {
		privkeyStr = dev.PrivateKey.String()
	}
	fmt.Printf("  private key: %s\n", privkeyStr)
	fmt.Printf("  listening port: %d\n", dev.ListenPort)
	for _, peer := range dev.Peers {
		printPeer(peer, opt.ShowCredential)
	}
}

func setConfig(opt setOption) {
	fin, err := os.Open(opt.Config)
	checkError(err)
	defer fin.Close()
	cfg, err := config.ParseConfig(fin)
	checkError(err)
	client, err := wgctrl.New()
	checkError(err)
	err = client.ConfigureDevice(opt.Interface, *cfg)
	checkError(err)
	log.Printf("interface %s configured.\n", opt.Interface)
}

func printPeer(peer wgtypes.Peer, showCredential bool) {
	const tmpl = `
peer: {{ .PublicKey }}
  preshared key = {{ .PresharedKey }}
  endpoint = {{ .Endpoint }}
  keep alive interval = {{ .KeepAliveInterval }}s
  last handshake time = {{ .LastHandshakeTime }}
  receive bytes = {{ .ReceiveBytes }}
  transmit bytes = {{ .TransmitBytes }}
  allowed ips = {{ .AllowedIPs }}
  protocol version = {{ .ProtocolVersion }} 
`

	type tmplContent struct {
		PublicKey         string
		PresharedKey      string
		Endpoint          string
		KeepAliveInterval float64
		LastHandshakeTime string
		ReceiveBytes      int64
		TransmitBytes     int64
		AllowedIPs        string
		ProtocolVersion   int
	}

	t := template.Must(template.New("peer_tmpl").Parse(tmpl))
	c := tmplContent{
		PublicKey:         peer.PublicKey.String(),
		PresharedKey:      "(hidden)",
		Endpoint:          peer.Endpoint.String(),
		KeepAliveInterval: peer.PersistentKeepaliveInterval.Seconds(),
		LastHandshakeTime: peer.LastHandshakeTime.Format(time.RFC3339),
		ReceiveBytes:      peer.ReceiveBytes,
		TransmitBytes:     peer.TransmitBytes,
		AllowedIPs:        "",
		ProtocolVersion:   peer.ProtocolVersion,
	}

	if showCredential {
		c.PresharedKey = peer.PresharedKey.String()
	}
	allowdIPStrings := make([]string, 0, len(peer.AllowedIPs))
	for _, v := range peer.AllowedIPs {
		allowdIPStrings = append(allowdIPStrings, v.String())
	}
	c.AllowedIPs = strings.Join(allowdIPStrings, ", ")
	t.Execute(os.Stdout, c)
}
