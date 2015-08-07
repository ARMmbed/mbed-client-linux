# NB external pthreads dependency!!
find_package (Threads)

add_library(mbed-client-linux
    m2mconnectionhandlerimpl.cpp
    m2mconnectionhandlerpimpl.cpp
    m2mtimerimpl.cpp
    m2mtimerpimpl.cpp
    connthreadhelper.cpp
    threadhelper.cpp
) 

target_link_libraries(mbed-client-linux
    ${CMAKE_THREAD_LIBS_INIT}
)


