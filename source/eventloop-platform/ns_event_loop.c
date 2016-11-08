/*
 * Copyright (c) 2016 ARM Limited, All Rights Reserved
 */

#include <pthread.h>
#include <semaphore.h>
#include <assert.h>
#include "ns_event_loop.h"
#include "ns_trace.h"
#include "eventOS_scheduler.h"

#define TRACE_GROUP "evlp"

static void* event_loop_thread(void *arg);

static pthread_t event_thread_id = 0;
static pthread_mutex_t event_mutex_id;
static pthread_mutexattr_t event_mutex_mutexattr;
static pthread_t event_mutex_owner_id = 0;
static uint32_t owner_count = 0;
static sem_t event_start_sema_id;
static sem_t event_signal_sema_id;

void eventOS_scheduler_mutex_wait(void)
{
    pthread_mutex_lock(&event_mutex_id);
    if (0 == owner_count) {
        event_mutex_owner_id = pthread_self();
    }
    owner_count++;
}

void eventOS_scheduler_mutex_release(void)
{
    owner_count--;
    if (0 == owner_count) {
        event_mutex_owner_id = 0;
    }
    pthread_mutex_unlock(&event_mutex_id);
}

uint8_t eventOS_scheduler_mutex_is_owner(void)
{
    return pthread_self() == event_mutex_owner_id ? 1 : 0;
}

void eventOS_scheduler_signal(void)
{
    int err = sem_post(&event_signal_sema_id);
    assert(err == 0);
}

void eventOS_scheduler_idle(void)
{
    eventOS_scheduler_mutex_release();
    int err = sem_wait(&event_signal_sema_id);
    assert(err == 0);
    eventOS_scheduler_mutex_wait();
}

static void* event_loop_thread(void *arg)
{
    tr_debug("event_loop_thread create");
    int err = sem_wait(&event_start_sema_id);
    assert(err == 0);
    eventOS_scheduler_mutex_wait();
    tr_debug("event_loop_thread");

    // Run does not return - it calls eventOS_scheduler_idle when it's, er, idle
    eventOS_scheduler_run();
}

void ns_event_loop_thread_create(void)
{
    int err = 0;
    err = sem_init(&event_start_sema_id, 0, 1);
    assert(err == 0);
    err = sem_wait(&event_start_sema_id);
    assert(err == 0);

    err = pthread_mutexattr_init(&event_mutex_mutexattr);
    assert(err == 0);
    err = pthread_mutexattr_settype(&event_mutex_mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);
    assert(err == 0);
    err = pthread_mutex_init(&event_mutex_id, &event_mutex_mutexattr);
    assert(err == 0);

    err = sem_init(&event_signal_sema_id, 0, 1);
    assert(err == 0);
    pthread_create(&event_thread_id, NULL, &event_loop_thread, NULL);
}

void ns_event_loop_thread_start(void)
{
    int err = sem_post(&event_start_sema_id);
    assert(err == 0);
}

void ns_event_loop_thread_cleanup(void)
{
    int err = pthread_cancel(event_thread_id);
    assert(err == 0);
    err = pthread_join(event_thread_id, NULL);
    assert(err == 0);
    err = pthread_mutex_destroy(&event_mutex_id);
    assert(err == 0);
    err = pthread_mutexattr_destroy(&event_mutex_mutexattr);
    assert(err == 0);
    err = sem_destroy(&event_start_sema_id);
    assert(err == 0);
    err = sem_destroy(&event_signal_sema_id);
}
