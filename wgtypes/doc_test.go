package wgtypes_test

import (
	"fmt"
	"log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// This file contains documentation examples

// Generate a Private key and Public Key.
func ExampleKey() {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	pub := priv.PublicKey()

	fmt.Println(pub)
}
