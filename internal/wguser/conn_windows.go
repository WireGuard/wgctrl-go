//+build windows

package wguser

import (
	"net"
	"strings"

	winio "github.com/microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Expected prefixes when dealing with named pipes.
const (
	pipePrefix = `\\.\pipe\`
	wgPrefix   = `WireGuard\`
)

// dial is the default implementation of Client.dial.
func dial(device string) (net.Conn, error) {
	return winio.DialPipe(device, nil)
}

// find is the default implementation of Client.find.
func find() ([]string, error) {
	var (
		pipes []string
		data  windows.Win32finddata
	)

	// Thanks @zx2c4 for the tips on the appropriate Windows APIs here:
	// https://א.cc/dHGpnhxX/c.
	h, err := windows.FindFirstFile(
		// Append * to find all named pipes.
		windows.StringToUTF16Ptr(pipePrefix+"*"),
		&data,
	)
	if err != nil {
		return nil, err
	}
	defer windows.Close(h)

	// Check the first file's name for a match, but also keep searching for
	// WireGuard named pipes until no more files can be iterated.
	for {
		name := windows.UTF16ToString(data.FileName[:])
		if strings.HasPrefix(name, wgPrefix) {
			// Concatenate strings directly as filepath.Join appears to break the
			// named pipe prefix convention.
			pipes = append(pipes, pipePrefix+name)
		}

		if err := windows.FindNextFile(h, &data); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return nil, err
		}
	}

	return pipes, nil
}
