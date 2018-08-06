package wguser

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const ok = `private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
fwmark=1
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
allowed_ip=192.168.4.4/32
endpoint=[abcd:23::33%2]:51820
last_handshake_time_sec=1
last_handshake_time_nsec=2
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
tx_bytes=38333
rx_bytes=2224
allowed_ip=192.168.4.6/32
persistent_keepalive_interval=111
endpoint=182.122.22.19:3233
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
tx_bytes=1212111
rx_bytes=1929999999
errno=0

`

const okSet = `set=1
private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a

`

func TestClientDevices(t *testing.T) {
	// Used to trigger "parse peers" mode easily.
	const okKey = "public_key=0000000000000000000000000000000000000000000000000000000000000000\n"

	tests := []struct {
		name string
		res  []byte
		ok   bool
		d    *wgtypes.Device
	}{
		{
			name: "invalid key=value",
			res:  []byte("foo=bar=baz"),
		},
		{
			name: "invalid public_key",
			res:  []byte("public_key=xxx"),
		},
		{
			name: "short public_key",
			res:  []byte("public_key=abcd"),
		},
		{
			name: "invalid fwmark",
			res:  []byte("fwmark=foo"),
		},
		{
			name: "invalid endpoint",
			res:  []byte(okKey + "endpoint=foo"),
		},
		{
			name: "invalid allowed_ip",
			res:  []byte(okKey + "allowed_ip=foo"),
		},
		{
			name: "error",
			res:  []byte("errno=2\n\n"),
		},
		{
			name: "ok",
			res:  []byte(ok),
			ok:   true,
			d: &wgtypes.Device{
				Name:       "testwg0",
				PrivateKey: wgtypes.Key{0xe8, 0x4b, 0x5a, 0x6d, 0x27, 0x17, 0xc1, 0x0, 0x3a, 0x13, 0xb4, 0x31, 0x57, 0x3, 0x53, 0xdb, 0xac, 0xa9, 0x14, 0x6c, 0xf1, 0x50, 0xc5, 0xf8, 0x57, 0x56, 0x80, 0xfe, 0xba, 0x52, 0x2, 0x7a}, PublicKey: wgtypes.Key{0xc1, 0x53, 0x2e, 0x1b, 0x3d, 0x35, 0x8, 0xfc, 0x7e, 0xbc, 0x35, 0x4f, 0xa6, 0x79, 0x62, 0xf, 0x33, 0xf2, 0x87, 0x14, 0x95, 0x42, 0xe6, 0x84, 0xc6, 0x7b, 0x7b, 0xd, 0x81, 0x36, 0x2b, 0x29},
				ListenPort:   12912,
				FirewallMark: 1,
				Peers: []wgtypes.Peer{
					{
						PublicKey:    wgtypes.Key{0xb8, 0x59, 0x96, 0xfe, 0xcc, 0x9c, 0x7f, 0x1f, 0xc6, 0xd2, 0x57, 0x2a, 0x76, 0xed, 0xa1, 0x1d, 0x59, 0xbc, 0xd2, 0xb, 0xe8, 0xe5, 0x43, 0xb1, 0x5c, 0xe4, 0xbd, 0x85, 0xa8, 0xe7, 0x5a, 0x33},
						PresharedKey: wgtypes.Key{0x18, 0x85, 0x15, 0x9, 0x3e, 0x95, 0x2f, 0x5f, 0x22, 0xe8, 0x65, 0xce, 0xf3, 0x1, 0x2e, 0x72, 0xf8, 0xb5, 0xf0, 0xb5, 0x98, 0xac, 0x3, 0x9, 0xd5, 0xda, 0xcc, 0xe3, 0xb7, 0xf, 0xcf, 0x52},
						Endpoint: &net.UDPAddr{
							IP:   net.ParseIP("abcd:23::33"),
							Port: 51820,
							Zone: "2",
						},
						LastHandshakeTime: time.Unix(1, 2),
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x4},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey:    wgtypes.Key{0x58, 0x40, 0x2e, 0x69, 0x5b, 0xa1, 0x77, 0x2b, 0x1c, 0xc9, 0x30, 0x97, 0x55, 0xf0, 0x43, 0x25, 0x1e, 0xa7, 0x7f, 0xdc, 0xf1, 0xf, 0xbe, 0x63, 0x98, 0x9c, 0xeb, 0x7e, 0x19, 0x32, 0x13, 0x76},
						PresharedKey: wgtypes.Key{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(182, 122, 22, 19),
							Port: 3233,
						},
						PersistentKeepaliveInterval: 111000000000,
						ReceiveBytes:                2224,
						TransmitBytes:               38333,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x6},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey: wgtypes.Key{0x66, 0x2e, 0x14, 0xfd, 0x59, 0x45, 0x56, 0xf5, 0x22, 0x60, 0x47, 0x3, 0x34, 0x3, 0x51, 0x25, 0x89, 0x3, 0xb6, 0x4f, 0x35, 0x55, 0x37, 0x63, 0xf1, 0x94, 0x26, 0xab, 0x2a, 0x51, 0x5c, 0x58},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(5, 152, 198, 39),
							Port: 51820,
						},
						ReceiveBytes:  1929999999,
						TransmitBytes: 1212111,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xa},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xb},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			devs, err := c.Devices()

			if tt.ok && err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff([]*wgtypes.Device{tt.d}, devs); diff != "" {
				t.Fatalf("unexpected Devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientDeviceByIndexIsNotExist(t *testing.T) {
	c := &Client{}

	// Hopefully there aren't this many interfaces on the test system.
	if _, err := c.DeviceByIndex(int(math.MaxUint16)); !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, but got: %v", err)
	}
}

func TestClientDeviceByName(t *testing.T) {
	tests := []struct {
		name   string
		device string
		exists bool
		d      *wgtypes.Device
	}{
		{
			name:   "not found",
			device: "wg1",
		},
		{
			name:   "ok",
			device: "testwg0",
			exists: true,
			d: &wgtypes.Device{
				Name:      "testwg0",
				PublicKey: wgtypes.Key{0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43, 0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29, 0x7, 0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2, 0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb, 0x3b, 0x74},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)
			defer done()

			dev, err := c.DeviceByName(tt.device)
			if err != nil {
				if !tt.exists && os.IsNotExist(err) {
					return
				}

				t.Fatalf("failed to get device: %v", err)
			}

			if diff := cmp.Diff(tt.d, dev); diff != "" {
				t.Fatalf("unexpected Device (-want +got):\n%s", diff)
			}
		})
	}
}

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
			device: "testwg0",
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

			if !tt.notExist && os.IsNotExist(err) {
				t.Fatalf("expected other error, but got not exist: %v", err)
			}
			if tt.notExist && !os.IsNotExist(err) {
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
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey: &wgtypes.Key{0xe8, 0x4b, 0x5a, 0x6d, 0x27, 0x17, 0xc1, 0x0, 0x3a, 0x13, 0xb4, 0x31, 0x57, 0x3, 0x53, 0xdb, 0xac, 0xa9, 0x14, 0x6c, 0xf1, 0x50, 0xc5, 0xf8, 0x57, 0x56, 0x80, 0xfe, 0xba, 0x52, 0x2, 0x7a},
			},
			req: okSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)

			if err := c.ConfigureDevice("testwg0", tt.cfg); err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}

			req := done()

			if diff := cmp.Diff(tt.req, string(req)); diff != "" {
				t.Fatalf("unexpected configure request (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_findSocketFiles(t *testing.T) {
	tmp, err := ioutil.TempDir(os.TempDir(), "wireguardcfg-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create a file which is not a device socket.
	f, err := ioutil.TempFile(tmp, "notwg")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	_ = f.Close()

	// Create a temporary UNIX socket and leave it open so it is picked up
	// as a socket file.
	path := filepath.Join(tmp, "testwg0.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer l.Close()

	files, err := findSocketFiles([]string{
		tmp,
		// Should gracefully handle non-existent directories and files.
		filepath.Join(tmp, "foo"),
		"/not/exist",
	})
	if err != nil {
		t.Fatalf("failed to find files: %v", err)
	}

	if diff := cmp.Diff([]string{path}, files); diff != "" {
		t.Fatalf("unexpected output files (-want +got):\n%s", diff)
	}
}

func testClient(t *testing.T, res []byte) (*Client, func() []byte) {
	tmp, err := ioutil.TempDir(os.TempDir(), "wireguardcfg-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}

	// Create a temporary UNIX socket and leave it open so it is picked up
	// as a socket file.
	path := filepath.Join(tmp, "testwg0.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}

	// When no response is specified, send "OK".
	if res == nil {
		res = []byte("errno=0\n\n")
	}

	// Request is passed to the caller on return from done func.
	var mu sync.Mutex
	req := make([]byte, 512)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		c, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return
			}

			panicf("failed to accept connection: %v", err)
		}
		defer c.Close()

		mu.Lock()
		defer mu.Unlock()

		// Pass request to the caller.
		n, err := c.Read(req)
		if err != nil {
			panicf("failed to read request: %v", err)
		}
		req = req[:n]

		if _, err := c.Write(res); err != nil {
			panicf("failed to write response: %v", err)
		}
	}()

	c := &Client{
		findSockets: func() ([]string, error) {
			return []string{path}, nil
		},
	}

	return c, func() []byte {
		mu.Lock()
		defer mu.Unlock()

		_ = c.Close()
		_ = l.Close()
		wg.Wait()
		_ = os.RemoveAll(tmp)

		return req
	}
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
