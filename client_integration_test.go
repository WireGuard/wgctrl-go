package wireguardctrl_test

import (
	"net"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/wireguardctrl"
)

func TestClientIntegration(t *testing.T) {
	c, err := wireguardctrl.New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("skipping, wireguardctrl is not available on this system")
		}

		t.Fatalf("failed to open client: %v", err)
	}
	defer c.Close()

	// TODO(mdlayher): expand upon this.

	t.Run("devices", func(t *testing.T) {
		devices, err := c.Devices()
		if err != nil {
			// It seems that not all errors returned by UNIX socket dialing
			// conform to os.IsPermission, so for now, be lenient and assume that
			// any error here means that permission was denied.
			t.Skipf("skipping, failed to get devices: %v", err)
		}

		for _, d := range devices {
			t.Logf("device: %s: %s", d.Name, d.PublicKey.String())

			dn, err := c.DeviceByName(d.Name)
			if err != nil {
				t.Fatalf("failed to get %q by name: %v", d.Name, err)
			}

			if diff := cmp.Diff(d, dn); diff != "" {
				t.Fatalf("unexpected Device from DeviceByName (-want +got):\n%s", diff)
			}

			// Fetch the interface index of the device to verify it can be fetched
			// properly by that index.
			ifi, err := net.InterfaceByName(d.Name)
			if err != nil {
				t.Fatalf("failed to get %q network interface: %v", d.Name, err)
			}

			di, err := c.DeviceByIndex(ifi.Index)
			if err != nil {
				t.Fatalf("failed to get %q by index: %v", d.Name, err)
			}

			if diff := cmp.Diff(d, di); diff != "" {
				t.Fatalf("unexpected Device from DeviceByIndex (-want +got):\n%s", diff)
			}

		}
	})
}
