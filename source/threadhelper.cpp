/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "include/threadhelper.h"

#include "lwm2m-client-linux/m2mconnectionhandlerimpl.h"
#include "lwm2m-client-linux/m2mtimerimpl.h"

M2MTimerImpl  *__timer_impl = NULL;
M2MConnectionHandlerImpl *__connection_impl = NULL;

void* __thread_poll_function(void* object)
{
    if(__timer_impl) {
       __timer_impl->thread_function(object);
    }
    return NULL;
}

void* __listen_data_function(void* object)
{
    if(__connection_impl) {
       __connection_impl->data_receive(object);
    }
    return NULL;
}
