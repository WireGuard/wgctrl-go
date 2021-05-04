package wguser

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A known device name used throughout unit and integration tests.
const testDevice = "wgtest0"

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
			device: testDevice,
			exists: true,
			d: &wgtypes.Device{
				Name:      testDevice,
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
				if !tt.exists && errors.Is(err, os.ErrNotExist) {
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
	t.Helper()

	// Create a temporary userspace device listener backed by a UNIX socket or
	// Windows named pipe.
	l, dir, done := testListen(t, testDevice)
	t.Logf("userspace device: %s", l.Addr())

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
		// Point the Client at our temporary userspace device listener.
		find: testFind(dir),
		dial: dial,
	}

	return c, func() []byte {
		mu.Lock()
		defer mu.Unlock()

		_ = c.Close()
		done()
		wg.Wait()

		return req
	}
}

func durPtr(d time.Duration) *time.Duration { return &d }
func keyPtr(k wgtypes.Key) *wgtypes.Key     { return &k }
func intPtr(v int) *int                     { return &v }
