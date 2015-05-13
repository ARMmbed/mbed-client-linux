# NB external pthreads dependency!!
find_package (Threads)

add_library(lwm2m-client-linux
    m2mconnectionhandlerimpl.cpp
    threadhelper.cpp
    m2mtimerimpl.cpp
) 

target_link_libraries(lwm2m-client-linux
    ${CMAKE_THREAD_LIBS_INIT}
)


