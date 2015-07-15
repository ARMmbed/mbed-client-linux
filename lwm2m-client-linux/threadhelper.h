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
