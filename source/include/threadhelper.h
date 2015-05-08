/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#ifndef THREAD_HELPER_H
#define THREAD_HELPER_H

class M2MConnectionHandlerImpl;
class M2MTimerImpl;
extern M2MTimerImpl  *__timer_impl;
extern M2MConnectionHandlerImpl *__connection_impl;


#ifdef __cplusplus
extern "C" {
#endif

void* __thread_poll_function(void* object);
void* __listen_data_function(void*);

#ifdef __cplusplus
}
#endif

#endif // THREAD_HELPER_H
