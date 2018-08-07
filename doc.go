// Package wireguardctrl enables control of WireGuard devices on multiple platforms.
//
// For more information on WireGuard, please see https://www.wireguard.com/.
//
//
// Overview
//
// wireguardctrl can control multiple types of WireGuard devices, including:
//
//   - Linux kernel module devices, via generic netlink
//   - userspace devices (e.g. wireguard-go), via the userspace configuration protocol
//
// In the future, if non-Linux operating systems choose to implement WireGuard
// natively, this package should also be extended to support the native
// interfaces of those operating systems.
//
// If you are aware of any efforts on this front, please file an issue:
// https://github.com/mdlayher/wireguardctrl/issues/new.
package wireguardctrl
