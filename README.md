# wireguardctrl [![Build Status](https://travis-ci.org/mdlayher/wireguardctrl.svg?branch=master)](https://travis-ci.org/mdlayher/wireguardctrl) [![GoDoc](https://godoc.org/github.com/mdlayher/wireguardctrl?status.svg)](https://godoc.org/github.com/mdlayher/wireguardctrl) [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/wireguardctrl)](https://goreportcard.com/report/github.com/mdlayher/wireguardctrl)

Package `wireguardctrl` enables control of WireGuard devices on multiple platforms.

For more information on WireGuard, please see <https://www.wireguard.com/>.

MIT Licensed.

## Overview

`wireguardctrl` can control multiple types of WireGuard devices, including:

- Linux kernel module devices, via generic netlink
- userspace devices (e.g. wireguard-go), via the userspace configuration protocol

In the future, if non-Linux operating systems choose to implement WireGuard
natively, this package should also be extended to support the native interface
of those operating systems.

If you are aware of any efforts on this front, please
[file an issue](https://github.com/mdlayher/wireguardctrl/issues/new).

This package implements WireGuard configuration protocol operations, enabling
the configuration of existing WireGuard devices. Operations such as creating
WireGuard devices, or applying IP addresses to those devices, are out of scope
for this package.
