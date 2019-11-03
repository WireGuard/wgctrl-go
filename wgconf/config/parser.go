package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Spec: https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8

type parseError struct {
	message string
	line    int
}

func (p parseError) Error() string {
	return fmt.Sprintf("Parse error: %s, (line %d)", p.message, p.line)
}

const (
	sectionInterface = "Interface"
	sectionPeer      = "Peer"
	sectionEmpty     = ""
)

var (
	commentPattern = regexp.MustCompile(`#.*$`)
)

func matchSectionHeader(s string) (string, bool) {
	re := regexp.MustCompile(`\[(?P<section>\w+)\]`)
	matched := re.MatchString(s)
	if !matched {
		return "", false
	}
	sec := re.ReplaceAllString(s, "${section}")
	return sec, true
}

type pair struct {
	key   string
	value string
}

func matchKeyValuePair(s string) (pair, bool) {
	re := regexp.MustCompile(`^\s*(?P<key>\w+)\s*=\s*(?P<value>.+)\s*$`)
	matched := re.MatchString(s)
	if !matched {
		return pair{}, false
	}
	key := re.ReplaceAllString(s, "${key}")
	value := re.ReplaceAllString(s, "${value}")
	return pair{key: key, value: value}, true
}

func LoadConfig(in io.Reader) (*wgtypes.Config, error) {
	sc := bufio.NewScanner(in)
	var cfg *wgtypes.Config = nil
	peers := make([]wgtypes.PeerConfig, 0, 10)

	currentSec := sectionEmpty
	var currentPeerConfig *wgtypes.PeerConfig = nil

	for lineNum := 0; sc.Scan(); lineNum++ {
		line := sc.Text()
		line = commentPattern.ReplaceAllString(line, "")
		if strings.TrimSpace(line) == "" {
			// skip comment line
			continue
		}
		if sec, matched := matchSectionHeader(line); matched {
			if sec == sectionInterface {
				if cfg != nil {
					return nil, parseError{message: "duplicated Interface section", line: lineNum}
				}
				cfg = &wgtypes.Config{}
			} else if sec == sectionPeer {
				if currentPeerConfig != nil {
					peers = append(peers, *currentPeerConfig)
				}
				currentPeerConfig = &wgtypes.PeerConfig{}
			} else {
				return nil, parseError{message: fmt.Sprintf("Unknown section: %s", sec), line: lineNum}
			}
			currentSec = sec
			continue
		} else if pair, matched := matchKeyValuePair(line); matched {
			var perr *parseError
			if currentSec == sectionEmpty {
				return nil, parseError{message: "invalid top level key-value pair", line: lineNum}
			}
			if currentSec == sectionInterface {
				perr = parseInterfaceField(cfg, pair)
			} else if currentSec == sectionPeer {
				perr = parsePeerField(currentPeerConfig, pair)
			}
			if perr != nil {
				perr.line = lineNum
				return nil, perr
			}
		}
	}
	if currentSec == sectionPeer {
		peers = append(peers, *currentPeerConfig)
	}
	if cfg == nil {
		return nil, parseError{message: "no Interface section found"}
	}
	cfg.Peers = peers
	return cfg, nil
}

func parseInterfaceField(cfg *wgtypes.Config, p pair) *parseError {
	switch p.key {
	case "PrivateKey":
		key, err := decodeKey(p.value)
		if err != nil {
			return err
		}
		cfg.PrivateKey = &key
	case "ListenPort":
		port, err := strconv.Atoi(p.value)
		if err != nil {
			return &parseError{message: err.Error()}
		}
		cfg.ListenPort = &port
	case "FwMark":
		return &parseError{message: "FwMark is not supported"}
	default:
		return &parseError{message: fmt.Sprintf("invalid key %s for Interface section", p.key)}
	}
	return nil
}

func parsePeerField(cfg *wgtypes.PeerConfig, p pair) *parseError {
	switch p.key {
	case "PublicKey":
		key, err := decodeKey(p.value)
		if err != nil {
			return err
		}
		cfg.PublicKey = key
	case "PresharedKey":
		key, err := decodeKey(p.value)
		if err != nil {
			return err
		}
		cfg.PresharedKey = &key
	case "AllowedIPs":
		allowedIPs := make([]net.IPNet, 0, 10)
		splitted := strings.Split(p.value, ",")
		for _, seg := range splitted {
			seg = strings.TrimSpace(seg)
			ip, err := parseIPNet(seg)
			if err != nil {
				return err
			}
			allowedIPs = append(allowedIPs, *ip)
		}
		cfg.AllowedIPs = allowedIPs
	case "Endpoint":
		addr, err := net.ResolveUDPAddr("udp", p.value)
		if err != nil {
			return &parseError{message: err.Error()}
		}
		cfg.Endpoint = addr
	case "PersistentKeepalive":
		if p.value == "off" {
			cfg.PersistentKeepaliveInterval = nil
			return nil
		}
		sec, err := strconv.Atoi(p.value)
		if err != nil {
			return &parseError{message: err.Error()}
		}
		duration := time.Second * time.Duration(sec)
		cfg.PersistentKeepaliveInterval = &duration
	default:
		return &parseError{message: fmt.Sprintf("invalid key %s for Peer section", p.key)}
	}
	return nil
}

func decodeKey(s string) (wgtypes.Key, *parseError) {
	key, err := wgtypes.ParseKey(s)
	if err != nil {
		return wgtypes.Key{}, &parseError{message: err.Error()}
	}
	return key, nil
}

func parseIPNet(s string) (*net.IPNet, *parseError) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, &parseError{message: err.Error()}
	}
	if ipnet == nil {
		return nil, &parseError{message: "invalid cidr string"}
	}
	return ipnet, nil
}
