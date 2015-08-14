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

#ifndef THREADHELPER_H
#define THREADHELPER_H

#include <pthread.h>

/**
*  Abstract class for Thread management
*/
class ThreadHelper
{
 public:

     /**
      *   Default Constructor for thread
      */
    ThreadHelper();

    /**
      *   virtual destructor
      */
    virtual ~ThreadHelper();

    /**
      *   Thread functionality Pure virtual function  , it will be re implemented in derived classes
      */
    virtual void run() = 0;

    /**
     *   Function to start thread.
     */
    bool start();

    /**
     *   Function to join thread.
     */
    bool join();

    /**
     *   Function to cancel thread.
     */
    bool cancel();

 private:

     /**
     *   private Function to create thread.
     */
     bool create_thread();

     /**
     *   Call back Function Passing to pthread create API
     */
     static void* thread_function(void* ptr);

public:

     pthread_t _thread_id;

friend class Test_ThreadHelper;
};

#endif // THREADHELPER_H
