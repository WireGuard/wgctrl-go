#/bin/sh

curl https://git.noconroy.net/wireguard-bsd.git/plain/src/if_wg.h -o if_wg.h

echo -e "//+build openbsd,amd64\n" > defs_openbsd_amd64.go
GOARCH=amd64 go tool cgo -godefs defs.go >> defs_openbsd_amd64.go

echo -e "//+build openbsd,386\n" > defs_openbsd_386.go
GOARCH=386 go tool cgo -godefs defs.go >> defs_openbsd_386.go

rm -rf if_wg.h _obj/
