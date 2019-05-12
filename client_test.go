package wgctrl

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
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
		cs: []wgClient{
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
		cs: []wgClient{
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
			var cs []wgClient
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
			var cs []wgClient
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

type testClient struct {
	CloseFunc           func() error
	DevicesFunc         func() ([]*wgtypes.Device, error)
	DeviceFunc          func(name string) (*wgtypes.Device, error)
	ConfigureDeviceFunc func(name string, cfg wgtypes.Config) error
}

func (c *testClient) Close() error                        { return c.CloseFunc() }
func (c *testClient) Devices() ([]*wgtypes.Device, error) { return c.DevicesFunc() }
func (c *testClient) Device(name string) (*wgtypes.Device, error) {
	return c.DeviceFunc(name)
}
func (c *testClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.ConfigureDeviceFunc(name, cfg)
}
