#ifndef _CYCLIC_TP_H_
#define _CYCLIC_TP_H_

#include <sys/sdt.h>

#define trace_start_work(i)                         \
    DTRACE_PROBE1(cyclic, cyclic_tp_start_work, i)

#define trace_end_work(i)                           \
    DTRACE_PROBE1(cyclic, cyclic_tp_end_work, i)

#endif /* _CYCLIC_TP_H_ */
