/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "include/timerthreadhelper.h"

#include "lwm2m-client-linux/m2mconnectionhandlerimpl.h"
#include "lwm2m-client-linux/m2mtimerimpl.h"

M2MTimerImpl  *__timer_impl = NULL;

void* __thread_poll_function(void* object)
{
    if(__timer_impl) {
       __timer_impl->thread_function(object);
    }
    return NULL;
}

