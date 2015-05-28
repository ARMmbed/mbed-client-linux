/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "lwm2m-client-linux/m2mtimerimpl.h"
#include "lwm2m-client/m2mtimerobserver.h"
#include "include/timerthreadhelper.h"
#include "lwm2m-client/m2mconfig.h"
#include "libService/ns_trace.h"

#define SLOT_NSECS (50000)

M2MTimerImpl& M2MTimerImpl::operator=(const M2MTimerImpl& other)
{
    if( this != &other){
        _single_shot= other._single_shot;
        _interval = other._interval;
        _started = other._started;
        _mtx = other._mtx;
        _rem_mtx = other._rem_mtx;
    }
    return *this;
}

// Prevents the use of copy constructor
M2MTimerImpl::M2MTimerImpl(const M2MTimerImpl& other)
:_observer(other._observer)
{
    this->operator=(other);
}

M2MTimerImpl::M2MTimerImpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _mtx((pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER),
  _rem_mtx((pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER),
  _started(0)
{
    __timer_impl = this;
}

M2MTimerImpl::~M2MTimerImpl()
{
    if (!pthread_equal(_timer_th, pthread_self())) {
        pthread_cancel(_timer_th);
    }
    __timer_impl = NULL;
}

void M2MTimerImpl::start_timer( uint64_t interval,
                                bool single_shot)
{
    tr_debug("M2MTimerImpl::start_timer Interval %ld, single_shot : %d", interval, single_shot);
    _single_shot = single_shot;
    _interval =  interval ;
    pthread_mutex_lock(&_mtx);
    if (_started) {
        stop_timer();
    }
    _started = 1;
    pthread_create(&_timer_th, NULL, __thread_poll_function, this);
    pthread_mutex_unlock(&_mtx);
}


void M2MTimerImpl::stop_timer()
{
    tr_debug("M2MTimerImpl::stop_timer Interval");
    _started = 0;
    if (pthread_equal(_timer_th, pthread_self())) {
        if (0 == pthread_cancel(_timer_th)) {
            pthread_join(_timer_th, NULL);
            pthread_mutex_unlock(&_rem_mtx);
        }
    }
    _interval = 0;
    _single_shot = true;
}

void M2MTimerImpl::timer_expired(bool single_shot)
{
    tr_debug("M2MTimerImpl::timer_expired() single_shot %d", _single_shot);
    _single_shot = single_shot;
    _started = 0;
    _observer.timer_expired();
    if(!_single_shot) {
        start_timer(_interval,_single_shot);
    }
}

void M2MTimerImpl::thread_function(void *object)
{
    tr_debug("M2MTimerImpl::thread_function()");
    if(object) {
        M2MTimerImpl *thread_object = (M2MTimerImpl*) object;
        pthread_mutex_lock(&thread_object->_rem_mtx);
        usleep(thread_object->_interval * 1000);
        pthread_mutex_unlock(&thread_object->_rem_mtx);
        pthread_detach(thread_object->_timer_th);
        thread_object->timer_expired(thread_object->_single_shot);
    }
}
