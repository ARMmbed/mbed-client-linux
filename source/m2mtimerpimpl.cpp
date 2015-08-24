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
    if(!_single_shot) {
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
