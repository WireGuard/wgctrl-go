# wireguardctrl [![Build Status](https://travis-ci.org/mdlayher/wireguardctrl.svg?branch=master)](https://travis-ci.org/mdlayher/wireguardctrl) [![GoDoc](https://godoc.org/github.com/mdlayher/wireguardctrl?status.svg)](https://godoc.org/github.com/mdlayher/wireguardctrl) [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/wireguardctrl)](https://goreportcard.com/report/github.com/mdlayher/wireguardctrl)

Package `wireguardctrl` provides unified access to WireGuard devices for both
Linux kernel and userspace WireGuard implementations.

Users are encouraged to use `wireguardctrl` directly, rather than `wireguardnl`
or `wireguardcfg`, as it provides an abstracted interface that works on both
Linux and non-Linux operating systems.

For more information on WireGuard, please see <https://www.wireguard.com/>.

MIT Licensed.
