//+build linux

package wgnl

import (
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// configAttrs creates the required netlink attributes to configure the device
// specified by name using the non-nil fields in cfg.
func configAttrs(name string, cfg wgtypes.Config) ([]netlink.Attribute, error) {
	attrs := []netlink.Attribute{{
		Type: wgh.DeviceAIfname,
		Data: nlenc.Bytes(name),
	}}

	if cfg.PrivateKey != nil {
		attrs = append(attrs, netlink.Attribute{
			Type: wgh.DeviceAPrivateKey,
			Data: (*cfg.PrivateKey)[:],
		})
	}

	return attrs, nil
}
