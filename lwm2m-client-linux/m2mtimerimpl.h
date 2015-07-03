/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#ifndef M2M_TIMER_IMPL_H
#define M2M_TIMER_IMPL_H

#include <stdint.h>
#include "include/threadhelper.h"

class M2MTimerObserver;

/**
 * @brief M2MTimerImpl
 * Private implementation class for timer, this can be
 * modified based on platform on which mbed client needs
 * to be used.
 */
class M2MTimerImpl : public ThreadHelper
{
public:

    // Prevents the use of assignment operator
    M2MTimerImpl& operator=(const M2MTimerImpl& other);

    // Prevents the use of copy constructor
    M2MTimerImpl(const M2MTimerImpl& other);

    /**
    * Constructor.
    */
    M2MTimerImpl(M2MTimerObserver& _observer);

    /**
    * Destructor.
    */
    virtual ~M2MTimerImpl();

    /**
     * Starts timer
     * @param interval Timer's interval in milliseconds
    * @param single_shot defines if timer is ticked
    * once or is it restarted everytime timer is expired.
    */
    void start_timer(uint64_t interval, bool single_shot = true);

    /**
    * Stops timer.
    * This cancels the ongoing timer.
    */
    void stop_timer();

    /**
    * Callback function for timer completion.
    */
    void timer_expired();

protected : // From ThreadHelper

    virtual void run();

private:

    M2MTimerObserver&   _observer;
    bool                _single_shot;
    uint64_t            _interval;
    volatile bool       _started;

    friend class Test_M2MTimerImpl_linux;
};

#endif // M2M_TIMER_IMPL_H
