package wgtypes_test

import (
	"fmt"
	"log"
	"math/rand"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// This file contains documentation examples

func ExampleGenerateKey() {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	pc := wgtypes.PeerConfig{
		PresharedKey: &psk,
	}
	fmt.Println(pc)
}

func ExampleGeneratePrivateKey() {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	conf := wgtypes.Config{
		PrivateKey: &priv,
	}
	fmt.Println(conf)
}

func init() {
	rand.Seed(1)
}

func ExampleNewKey() {
	bs := make([]byte, 32)

	_, err := rand.Read(bs)
	if err != nil {
		log.Fatal(err)
	}

	key, err := wgtypes.NewKey(bs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	// Output:
	// Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=
}

func ExampleParseKey() {
	key, err := wgtypes.ParseKey("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	// Output:
	// Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=
}

func ExampleKey_PublicKey() {
	priv, err := wgtypes.ParseKey("Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=")
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.PublicKey()

	fmt.Println(pub)
	// Output:
	// ZP/Mzlvt9BwNH9oqtuL0ZP8OW1foBBWfE8R6nSrM/nk=
}
