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

const (
	SIOCGWGSERV = C.SIOCGWGSERV
	SIOCGWGPEER = C.SIOCGWGPEER

	SizeofWGIP = C.sizeof_union_wg_ip

	WGStateNoSession = C.WG_STATE_NO_SESSION
	WGStateInitiator = C.WG_STATE_INITIATOR
	WGStateResponder = C.WG_STATE_RESPONDER
)

type WGGetServ C.struct_wg_get_serv

type WGGetPeer C.struct_wg_get_peer

type WGIP C.union_wg_ip

type WGCIDR C.struct_wg_cidr
