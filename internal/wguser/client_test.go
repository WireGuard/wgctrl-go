package wguser

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestClientDevice(t *testing.T) {
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
				Type:      wgtypes.Userspace,
				PublicKey: wgtypes.Key{0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43, 0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29, 0x7, 0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2, 0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb, 0x3b, 0x74},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)
			defer done()

			dev, err := c.Device(tt.device)
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
	req := make([]byte, 4096)

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
		find: func() ([]string, error) {
			return []string{path}, nil
		},
		dial: func(device string) (net.Conn, error) {
			return net.Dial("unix", device)
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

func durPtr(d time.Duration) *time.Duration { return &d }
func keyPtr(k wgtypes.Key) *wgtypes.Key     { return &k }
func intPtr(v int) *int                     { return &v }

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
