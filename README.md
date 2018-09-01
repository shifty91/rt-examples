# RT Examples #

## About ##

These example programs show howto implement user space realtime applications
with Linux.

## Build ##

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make -j8

## Tracing ##

In order to make sure that the examples actually work, the Linux tracing
infrastructure can be utilized.

### Cyclic ###

    $ sudo trace-cmd record -e 'sched:sched_switch' -e 'sched:sched_wakeup' ./cyclic
    $ kernelshark

![Cyclic Trace](cyclic.png)

### Deadline ###

    $ sudo trace-cmd record -e 'sched:sched_switch' -e 'sched:sched_wakeup' ./deadline
    $ kernelshark

![Deadline Trace](deadline.png)

### Signal ###

Signal measures the latency between a cyclic task wants to wake up and is
actually woken up. It signals the maximum latency to a printing thread using
pthread condition variables.

### LTTng ###

This example demonstrates howto utilize LTTng for user space tracing. Take
trace:

    $ ./cyclic_lttng &
    $ lttng-sessiond --daemonize
    $ lttng create my-session
    $ lttng enable-event --userspace cyclic:cyclic_tp
    $ lttng start
    $ sleep 5
    $ lttng stop
    $ lttng destroy
    $ babeltrace ~/lttng-traces/my-session-*

## Dependencies ##

- Linux version >= 3.14 for deadline scheduling
- LTTng: optional

## Author ##

Copyright (C) 2018 Kurt Kanzenbach <kurt@kmk-computers.de>

## License ##

GPL Version 2
