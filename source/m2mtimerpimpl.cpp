/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "mbed-client-linux/m2mtimerpimpl.h"
#include "mbed-client/m2mtimerobserver.h"

static void alarmFunction(int sigNumb, siginfo_t *si, void *uc);

M2MTimerPimpl::M2MTimerPimpl(M2MTimerObserver& observer)
: _observer(observer),
  _single_shot(true),
  _interval(0),
  _type(M2MTimerObserver::Notdefined),
  _intermediate_interval(0),
  _total_interval(0),
  _timer_id(0),
  _total_interval_expired(false)
{
}

M2MTimerPimpl::~M2MTimerPimpl()
{
    stop_timer();
}

void M2MTimerPimpl::start_timer( uint64_t interval,
                                 M2MTimerObserver::Type type,
                                 bool single_shot)
{
    _intermediate_interval = 0;
    _total_interval = 0;    
    _single_shot = single_shot;
    _interval = interval;
    _type = type;
    start();
}

void M2MTimerPimpl::start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type)
{
    _total_interval_expired = false;
    _intermediate_interval = intermediate_interval;
    _total_interval = total_interval;
    _interval = total_interval;
    _type = type;
    start();
}

void M2MTimerPimpl::stop_timer()
{
    if (_timer_id != 0) {
        timer_delete(_timer_id);
        _timer_id = 0;
    }
}

void M2MTimerPimpl::timer_expired()
{
    if (M2MTimerObserver::Dtls == _type) {
        _total_interval_expired = true;
    }
    _observer.timer_expired(_type);
    if(!_single_shot) {
        start_timer(_interval, _type, false);
    }
}

void M2MTimerPimpl::start()
{
    stop_timer();
    _timer_specs.it_value.tv_sec = _interval / 1000;
    _timer_specs.it_value.tv_nsec = (_interval % 1000) * 1000000;
    _timer_specs.it_interval.tv_sec = 0;
    _timer_specs.it_interval.tv_nsec = 0;

    if (!_single_shot) {
        _timer_specs.it_interval.tv_sec = _interval / 1000;
        _timer_specs.it_interval.tv_nsec = (_interval % 1000) * 1000000;
    }

    sigemptyset(&_signal_action.sa_mask);
    _signal_action.sa_flags = SA_SIGINFO;
    _signal_action.sa_sigaction = alarmFunction;

    memset(&_signal_event, 0, sizeof(_signal_event));
    _signal_event.sigev_notify = SIGEV_SIGNAL;
    _signal_event.sigev_value.sival_ptr = (void*) this;
    _signal_event.sigev_signo = SIGALRM;

    timer_create(CLOCK_MONOTONIC, &_signal_event, &_timer_id);
    sigaction(SIGALRM, &_signal_action, NULL);
    timer_settime(_timer_id, 0, &_timer_specs, NULL);
}

bool M2MTimerPimpl::is_total_interval_passed()
{
    return _total_interval_expired;
}

bool M2MTimerPimpl::is_intermediate_interval_passed()
{
    itimerspec timer_spec;
    if (_timer_id != 0 ) {
        timer_gettime(_timer_id, &timer_spec);
        timer_settime(_timer_id, 0, &timer_spec, NULL);

        uint64_t trigger = _total_interval - _intermediate_interval;
        uint64_t remaining = (timer_spec.it_value.tv_sec  * 1000) +
                (timer_spec.it_value.tv_nsec / 1000000);

        if (remaining <= trigger) {
            return true;
        }
    }
    return false;
}

void alarmFunction(int /*signumb*/, siginfo_t *si, void */*uc*/) {
    M2MTimerPimpl * timer = reinterpret_cast<M2MTimerPimpl *> (si->si_value.sival_ptr);
    if (timer) {
        timer->timer_expired();
    }
}
