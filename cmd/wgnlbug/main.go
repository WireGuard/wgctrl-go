// Command wgnlbug attempts to reproduce an issue that causes netlink to respond
// infinitely when configuring multiple peers with a large number of addresses
// using wireguardctrl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/internal/wgtest"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/mikioh/ipaddr"
)

func main() {
	var (
		dFlag = flag.String("d", "wg0", "WireGuard device")
		nFlag = flag.Int("n", 1, "number of peers to generate and add")
	)
	flag.Parse()

	c, err := wireguardctrl.New()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer c.Close()

	d, err := c.DeviceByName(*dFlag)
	if err != nil {
		log.Fatalf("failed to get device: %v", err)
	}

	fmt.Println("before:", d.Name)
	for _, p := range d.Peers {
		fmt.Printf("- peer: %s: %d IPs\n", p.PublicKey.String(), len(p.AllowedIPs))
	}

	var peers []wgtypes.PeerConfig
	for i := 0; i < *nFlag; i++ {
		cur, err := ipaddr.Parse("2001:db8::/119")
		if err != nil {
			log.Fatalf("failed to create cursor: %v", err)
		}

		var ips []net.IPNet
		for pos := cur.Next(); pos != nil; pos = cur.Next() {
			ips = append(ips, net.IPNet{
				IP:   pos.IP,
				Mask: net.CIDRMask(128, 128),
			})
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         wgtest.MustPublicKey(),
			ReplaceAllowedIPs: true,
			AllowedIPs:        ips,
		})
	}

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := c.ConfigureDevice(d.Name, cfg); err != nil {
		log.Fatalf("failed to configure %q: %v", d.Name, err)
	}

	dn, err := c.DeviceByName(d.Name)
	if err != nil {
		log.Fatalf("failed to get %q by name: %v", d.Name, err)
	}

	fmt.Println(" after:", dn.Name)
	for _, p := range dn.Peers {
		fmt.Printf("- peer: %s: %d IPs\n", p.PublicKey.String(), len(p.AllowedIPs))
	}
}
