//+build windows

package wguser

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/ipc/winpipe"
)

// isWINE determines if this test is running in WINE.
var isWINE = func() bool {
	// Reference: https://forum.winehq.org/viewtopic.php?t=4988.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Wine`, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No key; the tests don't appear to be running in WINE.
			return false
		}

		panicf("failed to query registry for WINE: %v", err)
	}
	defer k.Close()

	return true
}()

// testFind produces a Client.find function for integration tests.
func testFind(dir string) func() ([]string, error) {
	return func() ([]string, error) {
		return findNamedPipes(dir)
	}
}

// testListen creates a userspace device listener for tests, returning the
// directory where it can be found and a function to clean up its state.
func testListen(t *testing.T, device string) (l net.Listener, dir string, done func()) {
	t.Helper()

	// It appears that some of the system calls required for full named pipe
	// tests are not implemented in WINE, so skip tests that invoke this helper
	// if this isn't a real Windows install.
	if isWINE {
		t.Skip("skipping, creating a userspace device does not work in WINE")
	}

	// Attempt to create a unique name and avoid collisions.
	dir = fmt.Sprintf(`wguser-test%d\`, time.Now().Nanosecond())

	l, err := winpipe.Listen(pipePrefix+dir+device, nil)
	if err != nil {
		t.Fatalf("failed to create Windows named pipe: %v", err)
	}

	done = func() {
		_ = l.Close()
	}

	return l, dir, done
}
