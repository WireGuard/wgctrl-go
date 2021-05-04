package wguser

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const okSet = `set=1
private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
fwmark=0
replace_peers=true
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
endpoint=[abcd:23::33%2]:51820
replace_allowed_ips=true
allowed_ip=192.168.4.4/32
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
update_only=true
endpoint=182.122.22.19:3233
persistent_keepalive_interval=111
replace_allowed_ips=true
allowed_ip=192.168.4.6/32
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
replace_allowed_ips=true
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
public_key=e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c
remove=true

`

func TestClientConfigureDeviceError(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		cfg      wgtypes.Config
		res      []byte
		notExist bool
	}{
		{
			name:     "not found",
			device:   "wg1",
			notExist: true,
		},
		{
			name:   "bad errno",
			device: testDevice,
			res:    []byte("errno=1\n\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			err := c.ConfigureDevice(tt.device, tt.cfg)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			if !tt.notExist && errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected other error, but got not exist: %v", err)
			}
			if tt.notExist && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected not exist error, but got: %v", err)
			}
		})
	}
}

func TestClientConfigureDeviceOK(t *testing.T) {
	tests := []struct {
		name string
		cfg  wgtypes.Config
		req  string
	}{
		{
			name: "ok, none",
			req:  "set=1\n\n",
		},
		{
			name: "ok, clear key",
			cfg: wgtypes.Config{
				PrivateKey: &wgtypes.Key{},
			},
			req: "set=1\nprivate_key=0000000000000000000000000000000000000000000000000000000000000000\n\n",
		},
		{
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey:   keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         wgtest.MustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
						PresharedKey:      keyPtr(wgtest.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          wgtest.MustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   wgtest.MustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
						UpdateOnly:                  true,
						Endpoint:                    wgtest.MustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         wgtest.MustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
						Endpoint:          wgtest.MustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.10/32"),
							wgtest.MustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: wgtest.MustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
						Remove:    true,
					},
				},
			},
			req: okSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)

			if err := c.ConfigureDevice(testDevice, tt.cfg); err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}

			req := done()

			if want, got := tt.req, string(req); want != got {
				t.Fatalf("unexpected configure request:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}
}
