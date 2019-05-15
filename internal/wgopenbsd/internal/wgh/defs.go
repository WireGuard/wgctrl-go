//+build ignore

// TODO(mdlayher): attempt to integrate into x/sys/unix infrastructure.

package wgh

/*
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include "if_wg.h"
*/
import "C"

// Interface group types and constants.

const SIOCGIFGMEMB = C.SIOCGIFGMEMB

type Ifgroupreq C.struct_ifgroupreq

type Ifgreq C.struct_ifg_req

// WireGuard types and constants.

const SIOCGWGSERV = C.SIOCGWGSERV

type WGGetServ C.struct_wg_get_serv
