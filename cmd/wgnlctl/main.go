// Command wgnlctl is a testing utility for interacting with WireGuard generic
// netlink via package wireguardnl.
package main

import (
	"fmt"
	"log"

	"github.com/mdlayher/wireguard/wireguardnl"
)

func main() {
	c, err := wireguardnl.New()
	if err != nil {
		log.Fatalf("failed to open wireguardnl: %v", err)
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

func printDevice(d *wireguardnl.Device) {
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

func printPeer(p wireguardnl.Peer) {
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
		// TODO(mdlayher): iterate each address.
		p.AllowedIPs[0].String(),
		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
	)
}
