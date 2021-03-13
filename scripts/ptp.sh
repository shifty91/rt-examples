#!/bin/sh
#
# Copyright (C) 2021 Kurt Kanzenbach <kurt@kmk-computers.de>
#
# Example for running gPTP.
#

set -e

cd "$(dirname "$0")"

# Interface
IF=$1
[ -z $IF ] && IF="eth0"

# Kill already running daemons
pkill ptp4l || true
pkill phc2sys || true

# Start ptp
ptp4l -2 -H -i ${IF} --socket_priority=3 --tx_timestamp_timeout=40 -f ../configs/gPTP.cfg &

# Synchronize system to network time
phc2sys -s ${IF} -O 0 &

exit 0
