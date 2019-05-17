//+build ignore

// TODO(mdlayher): attempt to integrate into x/sys/unix infrastructure.

package wgh

/*
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <time.h>
#include "if_wg.h"
*/
import "C"

// Interface group types and constants.

const SIOCGIFGMEMB = C.SIOCGIFGMEMB

type Ifgroupreq C.struct_ifgroupreq

type Ifgreq C.struct_ifg_req

type Timespec C.struct_timespec

// WireGuard types and constants.

const (
	SIOCGWGSERV = C.SIOCGWGSERV
	SIOCGWGPEER = C.SIOCGWGPEER

	WGStateNoSession = C.WG_STATE_NO_SESSION
	WGStateInitiator = C.WG_STATE_INITIATOR
	WGStateResponder = C.WG_STATE_RESPONDER
)

type WGGetServ C.struct_wg_get_serv

type WGGetPeer C.struct_wg_get_peer

type WGIP C.union_wg_ip
