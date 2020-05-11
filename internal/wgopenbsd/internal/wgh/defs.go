//+build ignore

// TODO(mdlayher): attempt to integrate into x/sys/unix infrastructure.

package wgh

/*
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <time.h>
#include <net/if_wg.h>

// This is a copy of ifgroupreq but the union's *ifg_req variant is broken out
// into an explicit field, and the other variant is omitted and replaced with
// struct padding to the expected size.
#undef ifgr_groups
struct go_ifgroupreq {
	char	ifgr_name[IFNAMSIZ];
	u_int	ifgr_len;
	char    ifgr_pad1[-1 * (4 - sizeof(void*))];
	struct	ifg_req *ifgr_groups;
	char    ifgr_pad2[16 - sizeof(void*)];
};
*/
import "C"

// Interface group types and constants.

const (
	SIOCGIFGMEMB = C.SIOCGIFGMEMB

	SizeofIfgreq = C.sizeof_struct_ifg_req
)

type Ifgroupreq C.struct_go_ifgroupreq

type Ifgreq C.struct_ifg_req

type Timespec C.struct_timespec

// WireGuard types and constants.

type WGDataIO C.struct_wg_data_io

type WGInterfaceIO C.struct_wg_interface_io

type WGPeerIO C.struct_wg_peer_io

type WGAIPIO C.struct_wg_aip_io

type WGAIPData C.struct_wg_aip_data

const (
	SIOCGWG = C.SIOCGWG

	WG_INTERFACE_HAS_PUBLIC    = C.WG_INTERFACE_HAS_PUBLIC
	WG_INTERFACE_HAS_PRIVATE   = C.WG_INTERFACE_HAS_PRIVATE
	WG_INTERFACE_HAS_PORT      = C.WG_INTERFACE_HAS_PORT
	WG_INTERFACE_HAS_RTABLE    = C.WG_INTERFACE_HAS_RTABLE
	WG_INTERFACE_REPLACE_PEERS = C.WG_INTERFACE_REPLACE_PEERS

	SizeofWGInterfaceIO = C.sizeof_struct_wg_interface_io
)
