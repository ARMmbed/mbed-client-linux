#ifndef M2M_TIMER_PIMPL_H__
#define M2M_TIMER_PIMPL_H__

#include <stdint.h>
#include "threadhelper.h"

#include "mbed-client/m2mtimerobserver.h"

class M2MTimerPimpl : public ThreadHelper {
private:
    // Prevents the use of assignment operator
    M2MTimerPimpl& operator=(const M2MTimerPimpl& other);

    // Prevents the use of copy constructor
    M2MTimerPimpl(const M2MTimerPimpl& other);

    /**
    * Constructor.
    */
    M2MTimerPimpl(M2MTimerObserver& _observer);

    /**
    * Destructor.
    */
    virtual ~M2MTimerPimpl();

    /**
     * Starts timer
     * @param interval Timer's interval in milliseconds
    * @param single_shot defines if timer is ticked
    * once or is it restarted everytime timer is expired.
    */
    void start_timer(uint64_t interval, M2MTimerObserver::Type type, bool single_shot = true);

    /**
     * @brief Starts timer in DTLS manner
     * @param intermediate_interval Intermediate interval to use, must be smaller than tiotal (usually 1/4 of total)
     * @param total_interval Total interval to use; This is the timeout value of a DTLS packet
     * @param type Type of the timer
     */
    void start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type);

    /**
    * Stops timer.
    * This cancels the ongoing timer.
    */
    void stop_timer();

    /**
    * Callback function for timer completion.
    */
    void timer_expired();

    /**
     * @brief Checks if the intermediate interval has passed
     * @return true if interval has passed, false otherwise
     */
    bool is_intermediate_interval_passed();

    /**
     * @brief Checks if the total interval has passed
     * @return true if interval has passed, false otherwise
     */
    bool is_total_interval_passed();


protected : // From ThreadHelper

    virtual void run();

private:
    M2MTimerObserver&   _observer;
    bool                _single_shot;
    uint64_t            _interval;
    M2MTimerObserver::Type  _type;

    uint64_t            _intermediate_interval;
    uint64_t            _total_interval;
    uint8_t             _status;
    bool                _dtls_type;

    friend class M2MTimer;
    friend class Test_M2MTimerPimpl_linux;
};

#endif //M2M_TIMER_PIMPL_H__
