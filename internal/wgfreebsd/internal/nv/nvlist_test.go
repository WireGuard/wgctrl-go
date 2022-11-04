//go:build freebsd
// +build freebsd

package nv_test

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wgfreebsd/internal/nv"
)

func TestMarshaling(t *testing.T) {
	m1 := nv.List{
		"number":  uint64(0x1234),
		"boolean": true,
		"binary":  []byte{0xA, 0xB, 0xC, 0xD},
		"array_of_nvlists": []nv.List{
			{
				"a": uint64(1),
			},
			{
				"b": uint64(2),
			},
		},
	}

	buf, sz, err := nv.Marshal(m1)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	m2 := nv.List{}
	buf2 := unsafe.Slice(buf, sz)

	err = nv.Unmarshal(buf2, m2)
	if err != nil {
		t.Fatalf("Failed to marshal: %s", err)
	}

	if fmt.Sprint(m1) != fmt.Sprint(m2) {
		t.Fatalf("unequal: %+#v != %+#v", m1, m2)
	}
}
