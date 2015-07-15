# NB external pthreads dependency!!
find_package (Threads)

add_library(lwm2m-client-linux
    m2mconnectionhandlerimpl.cpp
    m2mconnectionhandlerpimpl.cpp
    m2mtimerimpl.cpp
    m2mtimerpimpl.cpp
    connthreadhelper.cpp
    threadhelper.cpp
) 

target_link_libraries(lwm2m-client-linux
    ${CMAKE_THREAD_LIBS_INIT}
)


