/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "include/connthreadhelper.h"

#include "lwm2m-client-linux/m2mconnectionhandlerimpl.h"

M2MConnectionHandlerImpl *__connection_impl = NULL;

void* __listen_data_function(void* object)
{
    if(__connection_impl) {
       __connection_impl->data_receive(object);
    }
    return NULL;
}
