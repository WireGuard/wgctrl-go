package wgtypes_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPreparedKeys(t *testing.T) {
	// Keys generated via "wg genkey" and "wg pubkey" for comparison
	// with this Go implementation.
	const (
		private = "GHuMwljFfqd2a7cs6BaUOmHflK23zME8VNvC5B37S3k="
		public  = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
	)

	priv, err := wgtypes.ParseKey(private)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
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

	// Perform ECDH key exchange: https://cr.yp.to/ecdh.html.
	sharedA, err := curve25519.X25519(privA[:], pubB[:])
	if err != nil {
		t.Fatalf("failed to perform X25519 A: %v", err)
	}
	sharedB, err := curve25519.X25519(privB[:], pubA[:])
	if err != nil {
		t.Fatalf("failed to perform X25519 B: %v", err)
	}

	if diff := cmp.Diff(sharedA, sharedB); diff != "" {
		t.Fatalf("unexpected shared secret (-want +got):\n%s", diff)
	}
}

func TestBadKeys(t *testing.T) {
	// Adapt to fit the signature used in the test table.
	parseKey := func(b []byte) (wgtypes.Key, error) {
		return wgtypes.ParseKey(string(b))
	}

	tests := []struct {
		name string
		b    []byte
		fn   func(b []byte) (wgtypes.Key, error)
	}{
		{
			name: "bad base64",
			b:    []byte("xxx"),
			fn:   parseKey,
		},
		{
			name: "short base64",
			b:    []byte("aGVsbG8="),
			fn:   parseKey,
		},
		{
			name: "short key",
			b:    []byte("xxx"),
			fn:   wgtypes.NewKey,
		},
		{
			name: "long base64",
			b:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZg=="),
			fn:   parseKey,
		},
		{
			name: "long bytes",
			b:    bytes.Repeat([]byte{0xff}, 40),
			fn:   wgtypes.NewKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			t.Logf("OK error: %v", err)
		})
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
