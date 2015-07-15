#include "lwm2m-client-linux/threadhelper.h"

ThreadHelper::ThreadHelper()
:_thread_id(0)
{
}

ThreadHelper::~ThreadHelper()
{
    pthread_cancel(_thread_id);
}

bool ThreadHelper::start()
{
   return create_thread();
}

bool ThreadHelper::join()
{
    bool success = true;
    int rc = pthread_join(_thread_id,NULL);
    rc = pthread_detach(_thread_id);
    if (rc != 0) {
        success = false;
    }
    return success;
}

bool ThreadHelper::cancel()
{
    bool success = true;
    if(_thread_id != 0) {
        int rc = pthread_cancel(_thread_id);
        _thread_id = 0;
        if (rc != 0) {
            success = false;
        }
    }
    return success;
}

void* ThreadHelper::thread_function(void* ptr)
{
    if(ptr) {
        ThreadHelper* p_this = static_cast<ThreadHelper*>(ptr);
        pthread_detach(p_this->_thread_id);
        p_this->run();
    }
    return NULL;
}

bool ThreadHelper::create_thread()
{
    bool success = true;
    int rc = pthread_create(&_thread_id, NULL, thread_function, this);
    if (rc != 0) {
        success = false;
    }
    return success;
}
