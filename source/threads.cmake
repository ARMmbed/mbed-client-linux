# NB external pthreads dependency!!
find_package (Threads)
find_library (RT rt)

target_link_libraries(mbed-client-linux
    ${CMAKE_THREAD_LIBS_INIT}
    ${RT}
)

set_target_properties(mbed-client-linux PROPERTIES COMPILE_FLAGS "-D_XOPEN_SOURCE=700")