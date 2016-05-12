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

#ifndef M2M_TIMER_PIMPL_H__
#define M2M_TIMER_PIMPL_H__

#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "mbed-client/m2mtimerobserver.h"

class M2MTimerPimpl {

public:
    /**
    * Constructor.
    */
    M2MTimerPimpl(M2MTimerObserver& _observer);

    /**
    * Destructor.
    */
    virtual ~M2MTimerPimpl();

    /**
    * Callback function for timer completion.
    */
    void timer_expired();

private:

    /**
     * Starts timer
     * @param interval Timer's interval in milliseconds
     * @param single_shot defines if timer is ticked
     * once or is it restarted everytime timer is expired.
     */
    void start_timer(uint64_t interval, M2MTimerObserver::Type type, bool single_shot = true);

    /**
     * @brief Starts timer in DTLS manner
     * @param intermediate_interval Intermediate interval to use, must be smaller than tiotal (usually 1/4 of total)
     * @param total_interval Total interval to use; This is the timeout value of a DTLS packet
     * @param type Type of the timer
     */
    void start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type);

    /**
     * Stops timer.
     * This cancels the ongoing timer.
     */
    void stop_timer();

    /**
     * @brief Checks if the intermediate interval has passed
     * @return true if interval has passed, false otherwise
     */
    bool is_intermediate_interval_passed();

    /**
     * @brief Checks if the total interval has passed
     * @return true if interval has passed, false otherwise
     */
    bool is_total_interval_passed();

    /**
     * @brief Start the timer
     */
    void start();

private:
    M2MTimerObserver&       _observer;
    bool                    _single_shot;
    uint64_t                _interval;
    M2MTimerObserver::Type  _type;
    uint64_t                _intermediate_interval;
    uint64_t                _total_interval;
    timer_t                 _timer_id;
    struct sigevent         _signal_event;
    struct itimerspec       _timer_specs;
    bool                    _total_interval_expired;

    friend class M2MTimer;
    friend class Test_M2MTimerPimpl_linux;
};

#endif //M2M_TIMER_PIMPL_H__
