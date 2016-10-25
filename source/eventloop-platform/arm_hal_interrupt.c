/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#include <pthread.h>
#include <assert.h>
#include "platform/arm_hal_interrupt.h"
#include "arm_hal_interrupt_private.h"

static uint8_t sys_irq_disable_counter;
static pthread_mutexattr_t critical_mutexattr;
static pthread_mutex_t critical_mutex_id;

void platform_critical_init(void)
{
    int err = pthread_mutexattr_init(&critical_mutexattr);
    assert(err == 0);
    err = pthread_mutexattr_settype(&critical_mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);
    assert(err == 0);
    err = pthread_mutex_init(&critical_mutex_id, &critical_mutexattr);
    assert(err == 0);
}

void platform_enter_critical(void)
{
    pthread_mutex_lock(&critical_mutex_id);
    sys_irq_disable_counter++;
}

void platform_exit_critical(void)
{
    --sys_irq_disable_counter;
    pthread_mutex_unlock(&critical_mutex_id);
}
