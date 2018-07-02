# RT Examples #

## About ##

These two example programs show howto implement cyclic user space realtime
applications with Linux.

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

## Dependencies ##

- Linux version >= 3.14 for deadline scheduling

## Author ##

Copyright (C) 2018 Kurt Kanzenbach <kurt@kmk-computers.de>

## License ##

GPL Version 2
