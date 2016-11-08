/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include "ns_types.h"
#include "platform/arm_hal_timer.h"
#include "platform/arm_hal_interrupt.h"

#define NSEC_IN_MS     1000000
#define NSEC_IN_S   1000000000

// Low precision platform tick timer variables
static void (*tick_timer_callback)(void);
static volatile bool    timer_initialized = false;
static pthread_t timer_listener;
#define TICK_TIMER_ID   1

static uint32_t timer_period_ms = 0;

static void add_10msec(struct timespec *ts)
{
    ts->tv_nsec += NSEC_IN_MS * timer_period_ms;
    if (ts->tv_nsec >= 1000000000) {
        ts->tv_nsec = ts->tv_nsec - NSEC_IN_S;
        ts->tv_sec += 1;
    }
}

static void* timer_thread(void *arg)
{
    (void)arg;
    int err = 0;
    struct timespec next_timeout_ts;
    err = clock_gettime(CLOCK_MONOTONIC, &next_timeout_ts);
    assert(err == 0);

    while(1) {
        // Determine absolute time we want to sleep until
        add_10msec(&next_timeout_ts);

        // Call nanosleep until error or no interrupt, ie. return code is 0
        do {
            err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_timeout_ts, NULL);
            assert(err == 0 || err == EINTR);
        } while(err == EINTR);

        // Done sleeping, call callback
        if (tick_timer_callback != NULL) {
            tick_timer_callback();
        }
    }
}

static void tick_timer_cleanup(void)
{
    platform_tick_timer_stop();
}

// Low precision platform tick timer
int8_t platform_tick_timer_register(void (*tick_timer_cb_handler)(void))
{
    // following atexit assumes tick_timer gets registered only once, might need to
    // do some checking here if we think it's possible for someone to register multiple times
    atexit(tick_timer_cleanup);
    tick_timer_callback = tick_timer_cb_handler;
    return TICK_TIMER_ID;
}

int8_t platform_tick_timer_start(uint32_t period_ms)
{
    // Create thread to wait for signal from timer
    timer_period_ms = period_ms;
    return pthread_create(&timer_listener, NULL, &timer_thread, NULL);
}

int8_t platform_tick_timer_stop(void)
{
    pthread_cancel(timer_listener);
    pthread_join(timer_listener, NULL);
    return 0;
}

