#!/bin/bash
set -x

# !! This script is meant for use in CI build use only !!

WGUSERDEV="wggo0"

KERNEL=$(uname -s)
if [ "$KERNEL" == "Linux" ]; then
    # Set up the WireGuard kernel module on Linux.
    sudo add-apt-repository -y ppa:wireguard/wireguard
    sudo apt-get --allow-unauthenticated -y update
    sudo apt-get --allow-unauthenticated -y install linux-headers-$(uname -r) wireguard-dkms wireguard-tools

    # Configure a WireGuard interface.
    sudo ip link add wg0 type wireguard
    sudo ip link set up wg0

    # Also allow the use of wireguard-go for additional testing.
    export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
else
    # Mac will automatically assign a device name if we specify "utun".
    WGUSERDEV="utun"
fi

# Set up and run wireguard-go on all OSes.
mkdir bin/
git clone git://git.zx2c4.com/wireguard-go
cd wireguard-go
make
sudo mv ./wireguard-go ../bin/wireguard-go
cd ..
sudo rm -rf ./wireguard-go
sudo ./bin/wireguard-go ${WGUSERDEV}
