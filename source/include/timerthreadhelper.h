/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#ifndef THREAD_HELPER_H
#define THREAD_HELPER_H

class M2MTimerImpl;
extern M2MTimerImpl  *__timer_impl;


#ifdef __cplusplus
extern "C" {
#endif

void* __thread_poll_function(void* object);

#ifdef __cplusplus
}
#endif

#endif // THREAD_HELPER_H
