/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#include <assert.h>
#include <signal.h>
#include <time.h>
#include "ns_types.h"
#include "platform/arm_hal_timer.h"
#include "platform/arm_hal_interrupt.h"

// Low precision platform tick timer variables
static void (*tick_timer_callback)(void);
static timer_t          tick_timer_id;
struct sigevent         signal_event;
struct itimerspec       timer_specs;
static volatile bool    timer_initialized = false;
#define TICK_TIMER_ID   1

void expired(union sigval sigval)
{
    if (tick_timer_callback != NULL) {
        tick_timer_callback();
    }
}

// static method for creating the timer, called implicitly by platform_tick_timer_register if
// timer was not enabled already
static void tick_timer_create(void)
{
    signal_event.sigev_notify = SIGEV_THREAD;
    signal_event.sigev_value.sival_ptr = NULL;
    signal_event.sigev_notify_function = expired;
    signal_event.sigev_notify_attributes = NULL;

    int ret = timer_create(CLOCK_MONOTONIC, &signal_event, &tick_timer_id);
    timer_initialized = true;
    assert(ret == 0);
}

// Low precision platform tick timer
int8_t platform_tick_timer_register(void (*tick_timer_cb_handler)(void))
{
    if (!timer_initialized) {
        tick_timer_create();
    }
    tick_timer_callback = tick_timer_cb_handler;
    return TICK_TIMER_ID;
}

int8_t platform_tick_timer_start(uint32_t period_ms)
{
    int8_t retval = -1;
    if (tick_timer_id != NULL) {
        timer_specs.it_value.tv_sec = period_ms / 1000;
        timer_specs.it_value.tv_nsec = (period_ms % 1000) * 1000000;
        timer_specs.it_interval.tv_sec = period_ms / 1000;
        timer_specs.it_interval.tv_nsec = (period_ms % 1000) * 1000000;
        retval = timer_settime(tick_timer_id, 0, &timer_specs, NULL);
    }

    return retval;
}

int8_t platform_tick_timer_stop(void)
{
    int8_t retval = -1;
    if (tick_timer_id != NULL) {
        timer_specs.it_value.tv_sec = 0;
        timer_specs.it_value.tv_nsec = 0;
        timer_specs.it_interval.tv_sec = 0;
        timer_specs.it_interval.tv_nsec = 0;

        retval = timer_settime(tick_timer_id, 0, &timer_specs, NULL);

    }
    return retval;
}
