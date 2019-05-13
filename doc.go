// Package wgctrl enables control of WireGuard devices on multiple platforms.
//
// For more information on WireGuard, please see https://www.wireguard.com/.
//
//   go get golang.zx2c4.com/wireguard/wgctrl
//
//
// Overview
//
// wgctrl can control multiple types of WireGuard devices, including:
//
//   - Linux kernel module devices, via generic netlink
//   - userspace devices (e.g. wireguard-go), via the userspace configuration protocol
//
// In the future, if non-Linux operating systems choose to implement WireGuard
// natively, this package should also be extended to support the native
// interfaces of those operating systems.
//
// If you are aware of any efforts on this front, please file an issue:
// https://golang.zx2c4.com/wireguard/wgctrl/issues/new.
//
// This package implements WireGuard configuration protocol operations, enabling
// the configuration of existing WireGuard devices. Operations such as creating
// WireGuard devices, or applying IP addresses to those devices, are out of scope
// for this package.
package wgctrl
