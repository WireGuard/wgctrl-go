//go:build darwin

package wguser

import (
	"os"
	"path/filepath"
)

const NET_EXT_APP_ID = "com.wireguard.macos.network-extension"

func altSockPaths() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(homeDir, "Library", "Containers", NET_EXT_APP_ID, "Data")
	return []string{path}, nil
}
