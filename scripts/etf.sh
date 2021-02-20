#!/bin/sh
#
# Copyright (C) 2021 Kurt Kanzenbach <kurt@kmk-computers.de>
#
# Example for Intel NICs such as i210/i225:
#  - Tx queue 0: Launch time enabled
#  - Tx queue 1: No launch time
#  - Tx queue 2: No launch time
#  - Tx queue 3: No launch time and default
#

set -e

# interface
IF=$1
[ -z $IF ] && IF="eth0"

# load needed kernel modules
modprobe sch_mqprio
modprobe sch_etf

# Setup Tx traffic steering
tc qdisc replace dev ${IF} handle 100 parent root mqprio num_tc 4 \
   map 3 3 2 1 0 3 3 3 3 3 3 3 3 3 3 3 \
   queues 1@0 1@1 1@2 1@3 \
   hw 0

# Setup etf: traffic class 0 (socket prio 4) for ETF
tc qdisc replace dev ${IF} parent 100:1 etf \
   clockid CLOCK_TAI \
   delta 500000 \
   offload

# Show end result
tc qdisc show dev ${IF}

exit 0
