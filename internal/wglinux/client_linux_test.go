//+build linux

package wglinux

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wglinux/internal/wgh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	okIndex = 1
	okName  = "wg0"
)

func TestLinuxClientDevicesEmpty(t *testing.T) {
	tests := []struct {
		name string
		fn   func() ([]string, error)
	}{
		{
			name: "no interfaces",
			fn: func() ([]string, error) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				panic("no devices; shouldn't call genetlink")
			})
			defer c.Close()

			c.interfaces = tt.fn

			ds, err := c.Devices()
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(0, len(ds)); diff != "" {
				t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLinuxClientIsNotExist(t *testing.T) {
	// TODO(mdlayher): not ideal but this test is not particularly load-bearing
	// and the entire *nltest ecosystem needs to be reworked.
	t.Skipf("skipping, genltest needs to be reworked")

	device := func(c *Client) error {
		_, err := c.Device("wg0")
		return err
	}

	configure := func(c *Client) error {
		return c.ConfigureDevice("wg0", wgtypes.Config{})
	}

	tests := []struct {
		name  string
		fn    func(c *Client) error
		msgs  []genetlink.Message
		errno unix.Errno
	}{
		{
			name: "name: empty",
			fn: func(c *Client) error {
				_, err := c.Device("")
				return err
			},
		},
		{
			name:  "name: ENODEV",
			fn:    device,
			errno: unix.ENODEV,
		},
		{
			name:  "name: ENOTSUP",
			fn:    device,
			errno: unix.ENOTSUP,
		},
		{
			name:  "configure: ENODEV",
			fn:    configure,
			errno: unix.ENODEV,
		},
		{
			name:  "configure: ENOTSUP",
			fn:    configure,
			errno: unix.ENOTSUP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				// We aren't creating a system call error; we are creating a
				// netlink error inside a message.
				return tt.msgs, genltest.Error(int(tt.errno))
			})
			defer c.Close()

			if err := tt.fn(c); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected is not exist, but got: %v", err)
			}
		})
	}
}

func TestLinuxClientIsPermission(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}
	if u.Uid == "0" {
		t.Skip("skipping, test must be run without elevated privileges")
	}

	c, ok, err := New()
	if err != nil {
		t.Fatalf("failed to create Client: %v", err)
	}
	if !ok {
		t.Skip("skipping, the WireGuard generic netlink API is not available")
	}

	defer c.Close()

	// Check for permission denied as unprivileged user.
	if _, err := c.Device("wgnotexist0"); !os.IsPermission(err) {
		t.Fatalf("expected permission denied, but got: %v", err)
	}
}

func Test_initClientNotExist(t *testing.T) {
	conn := genltest.Dial(func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// Simulate genetlink family not found.
		return nil, genltest.Error(int(unix.ENOENT))
	})

	_, ok, err := initClient(conn)
	if err != nil {
		t.Fatalf("failed to open Client: %v", err)
	}
	if ok {
		t.Fatal("the generic netlink API should not be available from genltest")
	}
}

func Test_parseRTNLInterfaces(t *testing.T) {
	// marshalAttrs creates packed netlink attributes with a prepended ifinfomsg
	// structure, as returned by rtnetlink.
	marshalAttrs := func(attrs []netlink.Attribute) []byte {
		ifinfomsg := make([]byte, syscall.SizeofIfInfomsg)

		return append(ifinfomsg, nltest.MustMarshalAttributes(attrs)...)
	}

	tests := []struct {
		name string
		msgs []syscall.NetlinkMessage
		ifis []string
		ok   bool
	}{
		{
			name: "short ifinfomsg",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.RTM_NEWLINK,
				},
				Data: []byte{0xff},
			}},
		},
		{
			name: "empty",
			ok:   true,
		},
		{
			name: "immediate done",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.NLMSG_DONE,
				},
			}},
			ok: true,
		},
		{
			name: "ok",
			msgs: []syscall.NetlinkMessage{
				// Bridge device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes("br0"),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
								Type: unix.IFLA_INFO_KIND,
								Data: nlenc.Bytes("bridge"),
							}}),
						},
					}),
				},
				// WireGuard device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								// Random junk to skip.
								{
									Type: 255,
									Data: nlenc.Uint16Bytes(0xff),
								},
								{
									Type: unix.IFLA_INFO_KIND,
									Data: nlenc.Bytes(wgKind),
								},
							}),
						},
					}),
				},
			},
			ifis: []string{okName},
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifis, err := parseRTNLInterfaces(tt.msgs)

			if tt.ok && err != nil {
				t.Fatalf("failed to parse interfaces: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.ifis, ifis); diff != "" {
				t.Fatalf("unexpected interfaces (-want +got):\n%s", diff)
			}
		})
	}
}

const familyID = 20

func testClient(t *testing.T, fn genltest.Func) *Client {
	family := genetlink.Family{
		ID:      familyID,
		Version: wgh.GenlVersion,
		Name:    wgh.GenlName,
	}

	conn := genltest.Dial(genltest.ServeFamily(family, fn))

	c, ok, err := initClient(conn)
	if err != nil {
		t.Fatalf("failed to open Client: %v", err)
	}
	if !ok {
		t.Fatal("the generic netlink API was not available from genltest")
	}

	c.interfaces = func() ([]string, error) {
		return []string{okName}, nil
	}

	return c
}

func diffAttrs(x, y []netlink.Attribute) string {
	// Make copies to avoid a race and then zero out length values
	// for comparison.
	xPrime := make([]netlink.Attribute, len(x))
	copy(xPrime, x)

	for i := 0; i < len(xPrime); i++ {
		xPrime[i].Length = 0
	}

	yPrime := make([]netlink.Attribute, len(y))
	copy(yPrime, y)

	for i := 0; i < len(yPrime); i++ {
		yPrime[i].Length = 0
	}

	return cmp.Diff(xPrime, yPrime)
}

func mustAllowedIPs(ipns []net.IPNet) []byte {
	ae := netlink.NewAttributeEncoder()
	if err := encodeAllowedIPs(ae, ipns); err != nil {
		panicf("failed to create allowed IP attributes: %v", err)
	}

	b, err := ae.Encode()
	if err != nil {
		panicf("failed to encode allowed IP attributes: %v", err)
	}

	return b
}

func durPtr(d time.Duration) *time.Duration { return &d }
func keyPtr(k wgtypes.Key) *wgtypes.Key     { return &k }
func intPtr(v int) *int                     { return &v }

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
