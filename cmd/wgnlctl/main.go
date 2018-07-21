// Command wgnlctl is a testing utility for interacting with WireGuard generic
// netlink via package wireguardnl.
package main

import (
	"fmt"
	"log"

	"github.com/mdlayher/wireguardnl"
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
		fmt.Printf("%#v\n", d)
	}
}
