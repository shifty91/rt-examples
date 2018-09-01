#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER cyclic

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./cyclic-tp.h"

#if !defined(_CYCLIC_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _CYCLIC_TP_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    cyclic,
    cyclic_tp,
    TP_ARGS(
        char *, string_arg,
        int, int_arg
    ),
    TP_FIELDS(
        ctf_string(string_field, string_arg)
        ctf_integer(int, int_field, int_arg)
        )
    )

#endif /* _CYCLIC_TP_H_ */

#include <lttng/tracepoint-event.h>
