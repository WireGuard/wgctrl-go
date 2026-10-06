package wgwindows

import (
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wgwindows/internal/ioctl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseDeviceTruncated(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{
			name: "nil buffer",
			buf:  nil,
		},
		{
			name: "empty buffer",
			buf:  []byte{},
		},
		{
			name: "less than interface size",
			buf:  make([]byte, unsafe.Sizeof(ioctl.Interface{})-1),
		},
		{
			name: "interface specifies 1 peer but buffer truncated",
			buf: func() []byte {
				var b ioctl.ConfigBuilder
				b.AppendInterface(&ioctl.Interface{PeerCount: 1})
				ifz, sz := b.Interface()
				return unsafe.Slice((*byte)(unsafe.Pointer(ifz)), sz)
			}(),
		},
		{
			name: "peer specifies 1 allowed IP but buffer truncated",
			buf: func() []byte {
				var b ioctl.ConfigBuilder
				b.AppendInterface(&ioctl.Interface{PeerCount: 1})
				b.AppendPeer(&ioctl.Peer{AllowedIPsCount: 1})
				ifz, sz := b.Interface()
				return unsafe.Slice((*byte)(unsafe.Pointer(ifz)), sz)
			}(),
		},
		{
			name: "peer specifies huge allowed IPs count",
			buf: func() []byte {
				var b ioctl.ConfigBuilder
				b.AppendInterface(&ioctl.Interface{PeerCount: 1})
				b.AppendPeer(&ioctl.Peer{AllowedIPsCount: 999999})
				ifz, sz := b.Interface()
				return unsafe.Slice((*byte)(unsafe.Pointer(ifz)), sz)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev, err := parseDevice("wg0", tc.buf)
			if err == nil {
				t.Fatalf("expected error for %s, got nil (device: %+v)", tc.name, dev)
			}
		})
	}
}

func TestParseDeviceValid(t *testing.T) {
	var b ioctl.ConfigBuilder
	privKey := [32]byte{1, 2, 3, 4}
	pubKey := [32]byte{5, 6, 7, 8}
	peerPubKey := [32]byte{9, 10, 11, 12}
	peerPsk := [32]byte{13, 14, 15, 16}

	ifz := &ioctl.Interface{
		Flags:      ioctl.InterfaceHasPrivateKey | ioctl.InterfaceHasPublicKey | ioctl.InterfaceHasListenPort,
		ListenPort: 51820,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		PeerCount:  1,
	}
	b.AppendInterface(ifz)

	var ep ioctl.RawSockaddrInet
	_ = ep.SetIP(net.ParseIP("192.0.2.1"), 51820)

	peer := &ioctl.Peer{
		Flags:               ioctl.PeerHasPublicKey | ioctl.PeerHasPresharedKey | ioctl.PeerHasEndpoint | ioctl.PeerHasPersistentKeepalive | ioctl.PeerHasProtocolVersion,
		ProtocolVersion:     1,
		PublicKey:           peerPubKey,
		PresharedKey:        peerPsk,
		PersistentKeepalive: 25,
		Endpoint:            ep,
		TxBytes:             1024,
		RxBytes:             2048,
		LastHandshake:       116444736000000000 + 10000000,
		AllowedIPsCount:     2,
	}
	b.AppendPeer(peer)

	var a1 ioctl.AllowedIP
	a1.AddressFamily = windows.AF_INET
	a1.Cidr = 32
	copy(a1.Address[:], net.ParseIP("10.0.0.1").To4())
	b.AppendAllowedIP(&a1)

	var a2 ioctl.AllowedIP
	a2.AddressFamily = windows.AF_INET6
	a2.Cidr = 64
	copy(a2.Address[:], net.ParseIP("fd00::1").To16())
	b.AppendAllowedIP(&a2)

	ifzPtr, sz := b.Interface()
	buf := unsafe.Slice((*byte)(unsafe.Pointer(ifzPtr)), sz)

	dev, err := parseDevice("wg0", buf)
	if err != nil {
		t.Fatalf("unexpected error parsing valid device: %v", err)
	}

	if dev.Name != "wg0" {
		t.Errorf("expected name wg0, got %s", dev.Name)
	}
	if dev.PrivateKey != wgtypes.Key(privKey) {
		t.Errorf("unexpected private key")
	}
	if dev.PublicKey != wgtypes.Key(pubKey) {
		t.Errorf("unexpected public key")
	}
	if dev.ListenPort != 51820 {
		t.Errorf("expected listen port 51820, got %d", dev.ListenPort)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(dev.Peers))
	}

	p := dev.Peers[0]
	if p.PublicKey != wgtypes.Key(peerPubKey) {
		t.Errorf("unexpected peer public key")
	}
	if p.PresharedKey != wgtypes.Key(peerPsk) {
		t.Errorf("unexpected preshared key")
	}
	if p.Endpoint == nil || p.Endpoint.IP.String() != "192.0.2.1" || p.Endpoint.Port != 51820 {
		t.Errorf("unexpected endpoint: %v", p.Endpoint)
	}
	if p.PersistentKeepaliveInterval != 25*time.Second {
		t.Errorf("unexpected keepalive: %v", p.PersistentKeepaliveInterval)
	}
	if p.ProtocolVersion != 1 {
		t.Errorf("expected protocol version 1, got %d", p.ProtocolVersion)
	}
	if p.TransmitBytes != 1024 || p.ReceiveBytes != 2048 {
		t.Errorf("unexpected tx/rx bytes: %d/%d", p.TransmitBytes, p.ReceiveBytes)
	}
	if len(p.AllowedIPs) != 2 {
		t.Fatalf("expected 2 allowed IPs, got %d", len(p.AllowedIPs))
	}
	if p.AllowedIPs[0].String() != "10.0.0.1/32" {
		t.Errorf("expected 10.0.0.1/32, got %s", p.AllowedIPs[0].String())
	}
	if p.AllowedIPs[1].String() != "fd00::1/64" {
		t.Errorf("expected fd00::1/64, got %s", p.AllowedIPs[1].String())
	}
}
