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
#include "CppUTest/TestHarness.h"
#include "test_m2mtimerpimpl_linux.h"
#include "common_stub.h"
#include <unistd.h>

extern void expired(union sigval sigval);
class TestObserver : public M2MTimerObserver {

public:
    TestObserver(){}
    virtual ~TestObserver(){}
    void timer_expired(M2MTimerObserver::Type){
        visited = true;
    }
    bool visited;

};

Test_M2MTimerPimpl_linux::Test_M2MTimerPimpl_linux()
{
    observer = new TestObserver();
    timer = new M2MTimerPimpl(*observer);
}

Test_M2MTimerPimpl_linux::~Test_M2MTimerPimpl_linux()
{
    delete observer;
    delete timer;
}

void Test_M2MTimerPimpl_linux::test_start_timer()
{
    common_stub::int_value = 1;
    timer->start_timer(100,M2MTimerObserver::Notdefined,true);
}

void Test_M2MTimerPimpl_linux::test_stop_timer()
{
    common_stub::int_value = 1;
    timer->start_timer(100,M2MTimerObserver::Notdefined,true);
    timer->stop_timer();
    CHECK(timer->_timer_id == 0);
}

void Test_M2MTimerPimpl_linux::test_timer_expired()
{
    timer->_single_shot = true;
    sigval test;
    test.sival_ptr = timer;
    expired(test);
    CHECK(observer->visited == true);

    observer->visited = false;
    timer->_single_shot = false;
    expired(test);
    CHECK(observer->visited == true);
}

void Test_M2MTimerPimpl_linux::test_start_dtls_timer()
{
    common_stub::int_value = 1;
    timer->start_dtls_timer(10, 100, M2MTimerObserver::Dtls);
}

void Test_M2MTimerPimpl_linux::test_is_intermediate_interval_passed()
{
    common_stub::int_value = 1;
    timer->start_dtls_timer(2500, 10000, M2MTimerObserver::Dtls);
    common_stub::int2_value = 9000;
    CHECK(false == timer->is_intermediate_interval_passed());
    common_stub::int2_value = 5000;
    CHECK(true == timer->is_intermediate_interval_passed());
}

void Test_M2MTimerPimpl_linux::test_is_total_interval_passed()
{
    common_stub::int_value = 1;
    timer->start_dtls_timer(250, 2000, M2MTimerObserver::Dtls);
    CHECK(false == timer->is_total_interval_passed());
    timer->timer_expired();
    CHECK(true == timer->is_total_interval_passed());
}
