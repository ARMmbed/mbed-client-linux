/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "lwm2m-client-linux/m2mtimerpimpl.h"
#include "lwm2m-client/m2mtimerobserver.h"

M2MTimerPimpl::M2MTimerPimpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _type(M2MTimerObserver::Notdefined),
  _intermediate_interval(0),
  _total_interval(0),
  _status(0),
  _dtls_type(false)
{

}

M2MTimerPimpl::~M2MTimerPimpl()
{
}

void M2MTimerPimpl::start_timer( uint64_t interval,
                                 M2MTimerObserver::Type type,
                                 bool single_shot)
{
    stop_timer();
    _dtls_type = false;
    _intermediate_interval = 0;
    _total_interval = 0;
    _status = 0;
    _single_shot = single_shot;
    _interval = interval;
    _type = type;
    start();
}

void M2MTimerPimpl::start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type)
{
    stop_timer();
    _dtls_type = true;
    _intermediate_interval = 0;
    _total_interval = 0;
    _status = 0;
    _type = type;
    start();
}

void M2MTimerPimpl::stop_timer()
{
    _interval = 0;
    _single_shot = true;
    usleep(1000);
    cancel();
}

void M2MTimerPimpl::timer_expired()
{
    _observer.timer_expired(_type);
    if(_single_shot) {
        stop_timer();
    } else {
        start_timer(_interval, _type, false);
    }
}

void M2MTimerPimpl::run()
{
    if(!_dtls_type){
        usleep(_interval * 1000);
        timer_expired();
    }else{
        usleep(_intermediate_interval * 1000);
        _status++;
        usleep((_total_interval - _intermediate_interval) * 1000);
        _status++;
        stop_timer();
    }
}

bool M2MTimerPimpl::is_intermediate_interval_passed()
{
    if( _status > 0 ){
        return true;
    }
    return false;
}

bool M2MTimerPimpl::is_total_interval_passed()
{
    if( _status > 1 ){
        return true;
    }
    return false;
}
