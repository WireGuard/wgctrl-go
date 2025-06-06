package wgctrl

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	errFoo = errors.New("some error")

	okDevice = &wgtypes.Device{Name: "wg0"}

	cmpErrors = cmp.Comparer(func(x, y error) bool {
		return x.Error() == y.Error()
	})
)

func TestClientClose(t *testing.T) {
	var calls int
	fn := func() error {
		calls++
		return nil
	}

	c := &Client{
		cs: []wginternal.Client{
			&testClient{CloseFunc: fn},
			&testClient{CloseFunc: fn},
		},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if diff := cmp.Diff(2, calls); diff != "" {
		t.Fatalf("unexpected number of clients closed (-want +got):\n%s", diff)
	}
}

func TestClientDevices(t *testing.T) {
	fn := func() ([]*wgtypes.Device, error) {
		return []*wgtypes.Device{okDevice}, nil
	}

	c := &Client{
		cs: []wginternal.Client{
			// Same device retrieved twice, but we don't check uniqueness.
			&testClient{DevicesFunc: fn},
			&testClient{DevicesFunc: fn},
		},
	}

	devices, err := c.Devices()
	if err != nil {
		t.Fatalf("failed to get devices: %v", err)
	}

	if diff := cmp.Diff(2, len(devices)); diff != "" {
		t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
	}
}

func TestClientDevice(t *testing.T) {
	type deviceFunc func(name string) (*wgtypes.Device, error)

	var (
		notExist = func(_ string) (*wgtypes.Device, error) {
			return nil, os.ErrNotExist
		}

		willPanic = func(_ string) (*wgtypes.Device, error) {
			panic("shouldn't be called")
		}

		returnDevice = func(_ string) (*wgtypes.Device, error) {
			return okDevice, nil
		}
	)

	tests := []struct {
		name string
		fns  []deviceFunc
		err  error
	}{
		{
			name: "first error",
			fns: []deviceFunc{
				func(_ string) (*wgtypes.Device, error) {
					return nil, errFoo
				},
				willPanic,
			},
			err: errFoo,
		},
		{
			name: "not found",
			fns: []deviceFunc{
				notExist,
				notExist,
			},
			err: os.ErrNotExist,
		},
		{
			name: "first not found",
			fns: []deviceFunc{
				notExist,
				returnDevice,
			},
		},
		{
			name: "first ok",
			fns: []deviceFunc{
				returnDevice,
				willPanic,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wginternal.Client
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					DeviceFunc: fn,
				})
			}

			c := &Client{cs: cs}

			d, err := c.Device("")

			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(okDevice, d); diff != "" {
				t.Fatalf("unexpected device (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientConfigureDevice(t *testing.T) {
	type configFunc func(name string, cfg wgtypes.Config) error

	var (
		notExist = func(_ string, _ wgtypes.Config) error {
			return os.ErrNotExist
		}

		willPanic = func(_ string, _ wgtypes.Config) error {
			panic("shouldn't be called")
		}

		ok = func(_ string, _ wgtypes.Config) error {
			return nil
		}
	)

	tests := []struct {
		name string
		fns  []configFunc
		err  error
	}{
		{
			name: "first error",
			fns: []configFunc{
				func(_ string, _ wgtypes.Config) error {
					return errFoo
				},
				willPanic,
			},
			err: errFoo,
		},
		{
			name: "not found",
			fns: []configFunc{
				notExist,
				notExist,
			},
			err: os.ErrNotExist,
		},
		{
			name: "first not found",
			fns: []configFunc{
				notExist,
				ok,
			},
		},
		{
			name: "first ok",
			fns: []configFunc{
				ok,
				willPanic,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wginternal.Client
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					ConfigureDeviceFunc: fn,
				})
			}

			c := &Client{cs: cs}

			err := c.ConfigureDevice("", wgtypes.Config{})
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientConfigureDeviceWithShim(t *testing.T) {
	type devicesFunc func() ([]*wgtypes.Device, error)
	type supportsFunc func(name string) (bool, error)

	var (
		ip           = wgtest.MustCIDR("192.0.2.0/32")
		peerKey      = wgtest.MustPublicKey()
		dummyPeerKey = wgtypes.Key{}
		device       = "wg0"

		notSupported = func(_ string) (bool, error) {
			return false, nil
		}

		supported = func(_ string) (bool, error) {
			return true, nil
		}

		returnsError = func(_ string) (bool, error) {
			return false, errFoo
		}

		peerHasIP = func() ([]*wgtypes.Device, error) {
			return []*wgtypes.Device{
				{
					Name: device,
					Peers: []wgtypes.Peer{
						{
							PublicKey: peerKey,
							AllowedIPs: []net.IPNet{
								ip,
							},
						},
					},
				},
			}, nil
		}

		peerDoesNotHaveIP = func() ([]*wgtypes.Device, error) {
			return []*wgtypes.Device{
				{
					Name: device,
					Peers: []wgtypes.Peer{
						{
							PublicKey:  peerKey,
							AllowedIPs: []net.IPNet{},
						},
					},
				},
			}, nil
		}

		otherPeerHasIP = func() ([]*wgtypes.Device, error) {
			return []*wgtypes.Device{
				{
					Name: device,
					Peers: []wgtypes.Peer{
						{
							PublicKey:  peerKey,
							AllowedIPs: []net.IPNet{},
						},
						{
							PublicKey: wgtest.MustPublicKey(),
							AllowedIPs: []net.IPNet{
								ip,
							},
						},
					},
				},
			}, nil
		}

		removeAllowedIP = wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: peerKey,
					AllowedIPs: []wgtypes.AllowedIPConfig{
						{
							IPNet:  ip,
							Remove: true,
						},
					},
				},
			},
		}

		removeAllowedIPUndone = wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: peerKey,
					AllowedIPs: []wgtypes.AllowedIPConfig{
						{
							IPNet:  ip,
							Remove: true,
						},
						{
							IPNet: ip,
						},
					},
				},
			},
		}

		simulateRemoveAllowedIP = wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: dummyPeerKey,
					AllowedIPs: []wgtypes.AllowedIPConfig{
						{
							IPNet: ip,
						},
					},
				},
				{
					PublicKey: peerKey,
				},
				{
					PublicKey: dummyPeerKey,
					Remove:    true,
				},
			},
		}

		addAllowedIP = wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: peerKey,
					AllowedIPs: []wgtypes.AllowedIPConfig{
						{
							IPNet: ip,
						},
					},
				},
			},
		}

		dontRemoveIP = wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: peerKey,
				},
			},
		}
	)

	tests := []struct {
		name       string
		supportsFn supportsFunc
		devicesFn  devicesFunc
		cfg        wgtypes.Config
		expectCfg  wgtypes.Config
		err        error
	}{
		{
			name:       "not supported + remove IP + peer has IP",
			supportsFn: notSupported,
			devicesFn:  peerHasIP,
			cfg:        removeAllowedIP,
			expectCfg:  simulateRemoveAllowedIP,
			err:        nil,
		},
		{
			name:       "not supported + remove IP + peer does not have IP",
			supportsFn: notSupported,
			devicesFn:  peerDoesNotHaveIP,
			cfg:        removeAllowedIP,
			expectCfg:  dontRemoveIP,
			err:        nil,
		},
		{
			name:       "not supported + remove IP + other peer has IP",
			supportsFn: notSupported,
			devicesFn:  otherPeerHasIP,
			cfg:        removeAllowedIP,
			expectCfg:  dontRemoveIP,
			err:        nil,
		},
		{
			name:       "not supported + remove IP undone",
			supportsFn: notSupported,
			devicesFn:  peerHasIP,
			cfg:        removeAllowedIPUndone,
			expectCfg:  addAllowedIP,
			err:        nil,
		},
		{
			name:       "not supported + don't remove IP",
			supportsFn: notSupported,
			devicesFn:  peerHasIP,
			cfg:        addAllowedIP,
			expectCfg:  addAllowedIP,
			err:        nil,
		},
		{
			name:       "supported + remove IP",
			supportsFn: supported,
			cfg:        removeAllowedIP,
			expectCfg:  removeAllowedIP,
			err:        nil,
		},
		{
			name:       "supported + don't remove IP",
			supportsFn: supported,
			cfg:        addAllowedIP,
			expectCfg:  addAllowedIP,
			err:        nil,
		},
		{
			name:       "probe error + remove IP",
			supportsFn: returnsError,
			cfg:        removeAllowedIP,
			expectCfg:  wgtypes.Config{},
			err:        errFoo,
		},
		{
			name:       "probe error + don't remove IP",
			supportsFn: returnsError,
			cfg:        addAllowedIP,
			expectCfg:  wgtypes.Config{},
			err:        errFoo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var finalCfg wgtypes.Config

			cs := WithShim(&testClient{
				ConfigureDeviceFunc: func(name string, cfg wgtypes.Config) error {
					finalCfg = cfg

					return nil
				},
				DevicesFunc:                 tt.devicesFn,
				SupportsAllowedIPRemoveFunc: tt.supportsFn,
			})

			c := &Client{cs: []wginternal.Client{cs}}

			err := c.ConfigureDevice(device, tt.cfg)
			if !errors.Is(err, tt.err) {
				t.Fatalf("unexpected error: got %s, want %s", err, tt.err)
			}

			if diff := cmp.Diff(tt.expectCfg, finalCfg); diff != "" {
				t.Fatalf("unexpected config (-want +got):\n%s", diff)
			}
		})
	}
}

type testClient struct {
	CloseFunc                   func() error
	DevicesFunc                 func() ([]*wgtypes.Device, error)
	DeviceFunc                  func(name string) (*wgtypes.Device, error)
	ConfigureDeviceFunc         func(name string, cfg wgtypes.Config) error
	SupportsAllowedIPRemoveFunc func(name string) (bool, error)
}

func (c *testClient) Close() error                        { return c.CloseFunc() }
func (c *testClient) Devices() ([]*wgtypes.Device, error) { return c.DevicesFunc() }
func (c *testClient) Device(name string) (*wgtypes.Device, error) {
	return c.DeviceFunc(name)
}

func (c *testClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.ConfigureDeviceFunc(name, cfg)
}

func (c *testClient) SupportsAllowedIPRemove(name string) (bool, error) {
	return c.SupportsAllowedIPRemoveFunc(name)
}
