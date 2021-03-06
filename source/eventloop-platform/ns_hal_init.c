/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#include "ns_hal_init.h"

#include "ns_types.h"
#include <stdlib.h>
#include <assert.h>

#include "arm_hal_interrupt_private.h"
#include "ns_event_loop.h"
#include "eventOS_scheduler.h"
#include "platform/arm_hal_timer.h"
#include "ns_trace.h"


void ns_hal_init(void *heap, size_t h_size, void (*passed_fptr)(heap_fail_t), mem_stat_t *info_ptr)
{
    static bool initted;
    if (initted) {
        return;
    }
    if (!heap) {
        heap = malloc(h_size);
        assert(heap);
        if (!heap) {
            return;
        }
    }
    platform_critical_init();
    ns_dyn_mem_init(heap, h_size, passed_fptr, info_ptr);
    eventOS_scheduler_init();
    ns_event_loop_thread_create();
    ns_event_loop_thread_start();
    initted = true;

    atexit(platform_critical_cleanup);
    atexit(ns_event_loop_thread_cleanup);
}
