//go:build ignore
// +build ignore

// TODO(mdlayher): attempt to integrate into x/sys/unix infrastructure.

package wgh

/*
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <time.h>
#include <net/if.h>

struct wg_data_io {
	char wgd_name[IFNAMSIZ];
	void *wgd_data;
	size_t wgd_size;
};

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

#define SIOCSWG _IOWR('i', 210, struct wg_data_io)
#define SIOCGWG _IOWR('i', 211, struct wg_data_io)
*/
import "C"

// Interface group types and constants.

const (
	SizeofIfgreq = C.sizeof_struct_ifg_req

	SIOCGWG = C.SIOCGWG
	SIOCSWG = C.SIOCSWG
)

type Ifgroupreq C.struct_go_ifgroupreq

type Ifgreq C.struct_ifg_req

type WGDataIO C.struct_wg_data_io
