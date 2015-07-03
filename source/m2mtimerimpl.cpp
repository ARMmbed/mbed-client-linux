/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "lwm2m-client-linux/m2mtimerimpl.h"
#include "lwm2m-client/m2mtimerobserver.h"
#include "lwm2m-client/m2mconfig.h"

M2MTimerImpl::M2MTimerImpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _started(false)
{
}

M2MTimerImpl::~M2MTimerImpl()
{
}

void M2MTimerImpl::start_timer( uint64_t interval,
                                bool single_shot)
{
    _single_shot = single_shot;
    _interval =  interval;
    _started = true;
    start();
}


void M2MTimerImpl::stop_timer()
{
    _interval = 0;
    _single_shot = true;
    _started = false;
    usleep(1000);
    cancel();
}

void M2MTimerImpl::timer_expired()
{
    _observer.timer_expired();
    if(_single_shot) {
        stop_timer();
    } else {
        start_timer(_interval,false);
    }
}

void M2MTimerImpl::run()
{
    usleep(_interval * 1000);
    timer_expired();
}
