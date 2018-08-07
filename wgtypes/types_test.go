package wgtypes_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/crypto/curve25519"
)

func TestPreparedKeys(t *testing.T) {
	// Keys generated via "wg genkey" and "wg pubkey" for comparison
	// with this Go implementation.
	const (
		private = "GHuMwljFfqd2a7cs6BaUOmHflK23zME8VNvC5B37S3k="
		public  = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
	)

	b, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	priv, err := wgtypes.NewKey(b)
	if err != nil {
		t.Fatalf("failed to convert to Key: %v", err)
	}

	if diff := cmp.Diff(private, priv.String()); diff != "" {
		t.Fatalf("unexpected private key (-want +got):\n%s", diff)
	}

	pub := priv.PublicKey()
	if diff := cmp.Diff(public, pub.String()); diff != "" {
		t.Fatalf("unexpected public key (-want +got):\n%s", diff)
	}
}

func TestKeyExchange(t *testing.T) {
	privA, pubA := mustKeyPair()
	privB, pubB := mustKeyPair()

	// Perform ECDH key exhange: https://cr.yp.to/ecdh.html.
	var sharedA, sharedB [32]byte
	curve25519.ScalarMult(&sharedA, privA, pubB)
	curve25519.ScalarMult(&sharedB, privB, pubA)

	if diff := cmp.Diff(sharedA, sharedB); diff != "" {
		t.Fatalf("unexpected shared secret (-want +got):\n%s", diff)
	}
}

func mustKeyPair() (private, public *[32]byte) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	return keyPtr(priv), keyPtr(priv.PublicKey())
}

func keyPtr(k wgtypes.Key) *[32]byte {
	b32 := [32]byte(k)
	return &b32
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
