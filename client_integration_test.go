package wireguardctrl_test

import (
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
			if os.IsPermission(err) {
				t.Skip("skipping, wireguardctrl may require elevated privileges")
			}

			t.Fatalf("failed to get devices: %v", err)
		}

		for _, d := range devices {
			t.Logf("device: %s: %s", d.Name, d.PublicKey.String())

			// For now, userspace devices don't fetch their interface index.
			if d.Index != 0 {
				di, err := c.DeviceByIndex(d.Index)
				if err != nil {
					t.Fatalf("failed to get %q by index: %v", d.Name, err)
				}

				if diff := cmp.Diff(d, di); diff != "" {
					t.Fatalf("unexpected Device from DeviceByIndex (-want +got):\n%s", diff)
				}
			}

			dn, err := c.DeviceByName(d.Name)
			if err != nil {
				t.Fatalf("failed to get %q by name: %v", d.Name, err)
			}

			if diff := cmp.Diff(d, dn); diff != "" {
				t.Fatalf("unexpected Device from DeviceByName (-want +got):\n%s", diff)
			}
		}
	})
}
