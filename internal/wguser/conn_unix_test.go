//+build !windows

package wguser

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUNIX_findUNIXSockets(t *testing.T) {
	tmp, err := ioutil.TempDir(os.TempDir(), "wireguardcfg-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create a file which is not a device socket.
	f, err := ioutil.TempFile(tmp, "notwg")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	_ = f.Close()

	// Create a temporary UNIX socket and leave it open so it is picked up
	// as a socket file.
	path := filepath.Join(tmp, "testwg0.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer l.Close()

	files, err := findUNIXSockets([]string{
		tmp,
		// Should gracefully handle non-existent directories and files.
		filepath.Join(tmp, "foo"),
		"/not/exist",
	})
	if err != nil {
		t.Fatalf("failed to find files: %v", err)
	}

	if diff := cmp.Diff([]string{path}, files); diff != "" {
		t.Fatalf("unexpected output files (-want +got):\n%s", diff)
	}
}

// testFind produces a Client.find function for integration tests.
func testFind(dir string) func() ([]string, error) {
	return func() ([]string, error) {
		return findUNIXSockets([]string{dir})
	}
}

// testListen creates a userspace device listener for tests, returning the
// directory where it can be found and a function to clean up its state.
func testListen(t *testing.T, device string) (l net.Listener, dir string, done func()) {
	t.Helper()

	tmp, err := ioutil.TempDir(os.TempDir(), "wguser-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}

	path := filepath.Join(tmp, device)
	path += ".sock"

	l, err = net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create UNIX socket: %v", err)
	}

	done = func() {
		_ = l.Close()
		_ = os.RemoveAll(tmp)
	}

	return l, tmp, done
}
