# NB external pthreads dependency!!
find_package (Threads)
find_library (RT rt)

add_library(mbed-client-linux
    m2mconnectionhandler.cpp
    m2mconnectionhandlerpimpl.cpp
    m2mtimer.cpp
    m2mtimerpimpl.cpp
    connthreadhelper.cpp	
) 

target_link_libraries(mbed-client-linux
    ${CMAKE_THREAD_LIBS_INIT}
    ${RT}
)


