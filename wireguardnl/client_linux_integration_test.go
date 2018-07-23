//+build linux

package wireguardnl_test

import (
	"os"
	"testing"

	"github.com/mdlayher/wireguard/wireguardnl"
)

func TestLinuxClientIntegration(t *testing.T) {
	c, err := wireguardnl.New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("skipping, wireguardnl is not available on this system")
		}

		t.Fatalf("failed to open client: %v", err)
	}
	defer c.Close()

	// TODO(mdlayher): expand upon this.

	t.Run("devices", func(t *testing.T) {
		devices, err := c.Devices()
		if err != nil {
			if os.IsPermission(err) {
				t.Skip("skipping, wireguardnl requires elevated privileges")
			}

			t.Fatalf("failed to get devices: %v", err)
		}

		for _, d := range devices {
			t.Logf("device: %s: %s", d.Name, d.PublicKey.String())
		}
	})
}
