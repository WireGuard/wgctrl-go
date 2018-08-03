package wireguardctrl

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	errFoo = errors.New("some error")

	okDevice = &Device{Name: "wg0"}
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
	fn := func() ([]*Device, error) {
		return []*Device{okDevice}, nil
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

func TestClientDeviceByIndex(t *testing.T) {
	type byIndexFunc func(index int) (*Device, error)

	var (
		notExist = func(_ int) (*Device, error) {
			return nil, os.ErrNotExist
		}

		willPanic = func(_ int) (*Device, error) {
			panic("shouldn't be called")
		}

		returnDevice = func(_ int) (*Device, error) {
			return okDevice, nil
		}
	)

	tests := []struct {
		name string
		fns  []byIndexFunc
		ok   bool
	}{
		{
			name: "first error",
			fns: []byIndexFunc{
				func(_ int) (*Device, error) {
					return nil, errFoo
				},
				willPanic,
			},
		},
		{
			name: "not found",
			fns: []byIndexFunc{
				notExist,
				notExist,
			},
		},
		{
			name: "first not found",
			fns: []byIndexFunc{
				notExist,
				returnDevice,
			},
			ok: true,
		},
		{
			name: "first ok",
			fns: []byIndexFunc{
				returnDevice,
				willPanic,
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wgClient
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					DeviceByIndexFunc: fn,
				})
			}

			c := &Client{cs: cs}

			d, err := c.DeviceByIndex(0)

			if tt.ok && err != nil {
				t.Fatalf("failed to get device: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
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

func TestClientDeviceByName(t *testing.T) {
	type byNameFunc func(name string) (*Device, error)

	var (
		notExist = func(_ string) (*Device, error) {
			return nil, os.ErrNotExist
		}

		willPanic = func(_ string) (*Device, error) {
			panic("shouldn't be called")
		}

		returnDevice = func(_ string) (*Device, error) {
			return okDevice, nil
		}

		errFoo = errors.New("some error")
	)

	tests := []struct {
		name string
		fns  []byNameFunc
		ok   bool
	}{
		{
			name: "first error",
			fns: []byNameFunc{
				func(_ string) (*Device, error) {
					return nil, errFoo
				},
				willPanic,
			},
		},
		{
			name: "not found",
			fns: []byNameFunc{
				notExist,
				notExist,
			},
		},
		{
			name: "first not found",
			fns: []byNameFunc{
				notExist,
				returnDevice,
			},
			ok: true,
		},
		{
			name: "first ok",
			fns: []byNameFunc{
				returnDevice,
				willPanic,
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wgClient
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					DeviceByNameFunc: fn,
				})
			}

			c := &Client{cs: cs}

			d, err := c.DeviceByName("")

			if tt.ok && err != nil {
				t.Fatalf("failed to get device: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
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

type testClient struct {
	CloseFunc         func() error
	DevicesFunc       func() ([]*Device, error)
	DeviceByIndexFunc func(index int) (*Device, error)
	DeviceByNameFunc  func(name string) (*Device, error)
}

func (c *testClient) Close() error                              { return c.CloseFunc() }
func (c *testClient) Devices() ([]*Device, error)               { return c.DevicesFunc() }
func (c *testClient) DeviceByIndex(index int) (*Device, error)  { return c.DeviceByIndexFunc(index) }
func (c *testClient) DeviceByName(name string) (*Device, error) { return c.DeviceByNameFunc(name) }
