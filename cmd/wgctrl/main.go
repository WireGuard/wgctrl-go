// Command wgctrl is a testing utility for interacting with WireGuard via package
// wireguardctrl.
package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/mdlayher/wireguardctrl"
)

func main() {
	c, err := wireguardctrl.New()
	if err != nil {
		log.Fatalf("failed to open wireguardctrl: %v", err)
	}
	defer c.Close()

	devices, err := c.Devices()
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	for _, d := range devices {
		printDevice(d)

		for _, p := range d.Peers {
			printPeer(p)
		}
	}
}

func printDevice(d *wireguardctrl.Device) {
	const f = `interface: %s
  public key: %s
  private key: (hidden)
  listening port: %d

`

	fmt.Printf(
		f,
		d.Name,
		d.PublicKey.String(),
		d.ListenPort)
}

func printPeer(p wireguardctrl.Peer) {
	const f = `peer: %s
  endpoint: %s
  allowed ips: %s
  latest handshake: %s
  transfer: %d B received, %d B sent

`

	fmt.Printf(
		f,
		p.PublicKey.String(),
		// TODO(mdlayher): get right endpoint with getnameinfo.
		p.Endpoint.String(),
		ipsString(p.AllowedIPs),
		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
	)
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}
