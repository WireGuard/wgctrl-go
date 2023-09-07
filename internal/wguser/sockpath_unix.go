//go:build !darwin && !windows

package wguser

func altSockPaths() ([]string, error) {
	return nil, nil
}
