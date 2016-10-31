/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <semaphore.h>
#include <assert.h>

#include "mbed-client-linux/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"

#include "eventOS_scheduler.h"
#include "eventOS_event.h"

#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

int8_t M2MConnectionHandlerPimpl::_tasklet_id = -1;

static M2MConnectionHandlerPimpl *connection_handler = NULL;
static sem_t socket_event_handled;
static int fd_stop_write = -1;
static int fd_stop_read = -1;

pthread_t socket_listener_thread;
void* __listener_thread(void*)
{
    if (connection_handler) {
        connection_handler->socket_listener();
    }
}

extern "C" void connection_event_handler(arm_event_s *event)
{

    if(!connection_handler){
        return;
    }

    switch(event->event_type){

        case M2MConnectionHandlerPimpl::ESocketReadytoRead:

            connection_handler->receive_handler();
            sem_post(&socket_event_handled);
            break;

        case M2MConnectionHandlerPimpl::ESocketSend:

            connection_handler->send_socket_data((uint8_t*)event->data_ptr, event->event_data);
            free(event->data_ptr);
            break;

        case M2MConnectionHandlerPimpl::ESocketDnsHandler:

            connection_handler->dns_handler();
            break;

        default:

            break;

    }

}

void M2MConnectionHandlerPimpl::send_receive_event(void)
{
    arm_event_s event;
    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketReadytoRead;
    event.data_ptr = NULL;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    eventOS_event_send(&event);

}


M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity* sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _binding_mode(mode),
 _network_stack(stack),
 _socket(-1),
 _is_handshaking(false),
 _listening(true),
 _server_type(M2MConnectionObserver::LWM2MServer),
 _server_port(0),
 _listen_port(0),
 _running(false),
 _net_iface(0),
 _socket_address_len(0)
{

    memset(&_address, 0, sizeof _address);
    memset(&_socket_address, 0, sizeof(struct sockaddr_storage));

    connection_handler = this;

    int err = sem_init(&socket_event_handled, 0, 1);
    assert(err == 0);

    eventOS_scheduler_mutex_wait();
    if (M2MConnectionHandlerPimpl::_tasklet_id == -1) {
        M2MConnectionHandlerPimpl::_tasklet_id = eventOS_event_handler_create(&connection_event_handler, ESocketIdle);
    }
    eventOS_scheduler_mutex_release();

}

void M2MConnectionHandlerPimpl::socket_listener()
{
    while (_listening && _socket) {
        int sock = _socket;
        ssize_t err;
        fd_set read_set;
        int8_t input[1];
        FD_ZERO(&read_set);
        // Add socket to read set
        FD_SET(sock, &read_set);
        // Add stop pipe to read set
        FD_SET(fd_stop_read, &read_set);
        int max_fd = sock > fd_stop_read ? sock : fd_stop_read;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) == -1) {
            return;
        }

        if (FD_ISSET(fd_stop_read, &read_set)) {
            // We were signaled to stop reading so quit
            tr_debug("socket_listener() - got signal, stopping");
            break;
        }

        if (FD_ISSET(sock, &read_set)) {
            // Socket is ready to read, signal connection handler to read socket
            send_receive_event();
            sem_wait(&socket_event_handled);
        }
    }

    // Close socket if it wasn't already closed
    close_socket();

    // Cleanup stop pipe handler
    if (fd_stop_read >= 0) {
        close(fd_stop_read);
        fd_stop_read = -1;
    }
    tr_debug("M2MConnectionHandlerPimpl - listener finished");
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    stop_listening();
    sem_destroy(&socket_event_handled);

    delete _security_impl;
    tr_debug("~M2MConnectionHandlerPimpl() - OUT");
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    _listen_port = listen_port;
    return true;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                       const uint16_t server_port,
                                                       M2MConnectionObserver::ServerType server_type,
                                                       const M2MSecurity* security)
{

    arm_event_s event;

    tr_debug("resolve_server_address()");

    _security = security;
    _server_port = server_port;
    _server_type = server_type;
    _server_address = server_address;

    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketDnsHandler;
    event.data_ptr = NULL;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;

    return !eventOS_event_send(&event);

}

void M2MConnectionHandlerPimpl::dns_handler()
{
    struct addrinfo _hints;
    struct addrinfo *addr_info = NULL;
    bool success = false;
    tr_debug("M2MConnectionHandlerPimpl::dns_handler - IN");

    memset(&_hints, 0, sizeof(struct addrinfo));
    if(_network_stack == M2MInterface::LwIP_IPv4 ||
       _network_stack == M2MInterface::ATWINC_IPv4) {
        _hints.ai_family = AF_INET;
    }
    else if (_network_stack == M2MInterface::LwIP_IPv6 ||
            _network_stack == M2MInterface::Nanostack_IPv6) {
        _hints.ai_family = AF_INET6;
    }
    else {
        _hints.ai_family = AF_UNSPEC;
    }

    if (is_tcp_connection()) {
        _hints.ai_socktype = SOCK_STREAM;
        _hints.ai_protocol = IPPROTO_TCP;
    }
    else {
        _hints.ai_socktype = SOCK_DGRAM;
        _hints.ai_protocol = IPPROTO_UDP;
    }

    int status = getaddrinfo(_server_address.c_str(), NULL, &_hints, &addr_info);
    if (status == 0 && addr_info) {
        char ip_address[INET6_ADDRSTRLEN];
        while(addr_info) {
            close_socket();
            if(!init_socket()) {
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - init socket fail");
                break;
            }
            // Load socket address from result entry
            memset(&_socket_address, 0, sizeof(struct sockaddr_storage));
            memcpy(&_socket_address, addr_info->ai_addr, addr_info->ai_addrlen);
            // Store length
            _socket_address_len = addr_info->ai_addrlen;
            switch(_socket_address.ss_family) {
                case AF_INET:
                {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&_socket_address;
                    sin->sin_port = ntohs(_server_port);
                    inet_ntop(sin->sin_family, &sin->sin_addr, ip_address, INET_ADDRSTRLEN);
                    // Store address to M2MConnectionObserver::SocketAddress
                    _address._port = _server_port;
                    _address._stack = M2MInterface::LwIP_IPv4;
                    _address._length = 4;
                    _address._address = &sin->sin_addr;
                    if (connect(_socket, (const struct sockaddr *)&_socket_address, _socket_address_len) != 0) {
                        success = false;
                        tr_error("M2MConnectionHandlerPimpl::dns_handler - failed to connect %s, %s", ip_address, strerror(errno));
                    } else {
                        success = true;
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - connected to %s\n", ip_address);
                    }
                    break;
                }
                case AF_INET6:
                {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&_socket_address;
                    sin6->sin6_port = ntohs(_server_port);
                    inet_ntop(sin6->sin6_family, &sin6->sin6_addr, ip_address, INET6_ADDRSTRLEN);
                    // Store address to M2MConnectionObserver::SocketAddress
                    _address._port = _server_port;
                    _address._stack = M2MInterface::LwIP_IPv6;
                    _address._length = 16;
                    _address._address = &sin6->sin6_addr;
                    if (connect(_socket, (const struct sockaddr *)&_socket_address, _socket_address_len) != 0) {
                        success = false;
                        tr_error("M2MConnectionHandlerPimpl::dns_handler - failed to connect %s, %s", ip_address, strerror(errno));
                    } else {
                        success = true;
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - connected to %s\n", ip_address);
                    }
                    break;
                }
            }
            if (success) {
                break; // Working connection found, exit from loop
            }
            addr_info = addr_info->ai_next;
        }
    }

    freeaddrinfo(addr_info);

    if (!success) {
        tr_error("M2MConnectionHandlerPimpl::dns_handler - No connection");
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT, false);
        close_socket();
        tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
        return;
    }

    start_listening_for_data();
    _running = true;

    if (_security) {
        if (_security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk) {

            if( _security_impl != NULL ){
                _security_impl->reset();
                if (_security_impl->init(_security) == 0) {
                    _is_handshaking = true;
                    tr_debug("dns_handler - connect DTLS");
                    if(_security_impl->start_connecting_non_blocking(_base) < 0 ){
                        tr_debug("dns_handler - handshake failed");
                        _is_handshaking = false;
                        _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR);
                        close_socket();
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
                        return;
                    }
                } else {
                    tr_error("dns_handler - init failed");
                    _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                    close_socket();
                    tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
                    return;
                }
            } else {
                tr_error("dns_handler - sec is null");
                _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, false);
                close_socket();
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
                return;
            }
        }
    }
    if(!_is_handshaking) {
        enable_keepalive();
        _observer.address_ready(_address,
                                _server_type,
                                _address._port);
    }
    tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                          uint16_t data_len,
                                          sn_nsdl_addr_s *address)
{

    arm_event_s event;

    tr_debug("send_data()");
    if (address == NULL || data == NULL || !data_len || !_running) {
        return false;
    }

    event.data_ptr = (uint8_t*)malloc(data_len);
    if(!event.data_ptr) {
        return false;
    }
    memcpy(event.data_ptr, data, data_len);

    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketSend;
    event.event_data = data_len;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;

    if (eventOS_event_send(&event) != 0) {
        // Event push failed, free the buffer
        free(event.data_ptr);
        return false;
    }

    return true;

}

void M2MConnectionHandlerPimpl::send_socket_data(uint8_t *data, uint16_t data_len)
{

    ssize_t sent_len;
    bool success = false;
    int error = 0;

    if(!data || ! data_len || !_running)
    {
        return;
    }


    tr_debug("send_handler()");

    if( _use_secure_connection ){
        if( _security_impl->send_message(data, data_len) > 0){
            success = true;
        }
    } else {

        if(is_tcp_connection()){
            //We need to "shim" the length in front
            uint16_t d_len = data_len+4;
            uint8_t* d = (uint8_t*)malloc(data_len+4);

            if(d){

                d[0] = (data_len >> 24 )& 0xff;
                d[1] = (data_len >> 16 )& 0xff;
                d[2] = (data_len >> 8 )& 0xff;
                d[3] = data_len & 0xff;
                memcpy(d + 4, data, data_len);
                sent_len = sendto(_socket, d, d_len, 0, (const sockaddr*)&_socket_address, _socket_address_len);
                error = errno;
                free(d);

            }

        } else {
            sent_len = sendto(_socket, data, data_len, 0, (const sockaddr*)&_socket_address, _socket_address_len);
            error = errno;
        }
        if (sent_len != -1) {
            success = true;
        }
    }

    if (!success) {
        tr_error("M2MConnectionHandlerPimpl::send_socket_data - sendto error: %s", strerror(error));
        _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR, true);
        close_socket();
    }
    else{
        _observer.data_sent();
    }


}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{

    tr_debug("start_listening_for_data()");

    _listening = true;

    // Prepare a pipe for signaling listening thread when we want to stop
    if (fd_stop_write < 0 && fd_stop_read < 0) {
        int stop_pipe[2];
        if (pipe(stop_pipe)) {
            perror("stop pipe creation failed");
            abort();
        }
        fd_stop_read = stop_pipe[0];
        fd_stop_write = stop_pipe[1];
    }
    else {
        perror("Stop pipe was already created!");
    }

    pthread_create(&socket_listener_thread, NULL,__listener_thread, NULL);

    return true;

}

void M2MConnectionHandlerPimpl::stop_listening()
{

    tr_debug("stop_listening()");

    _listening = false;

    // write to stop pipe to signal listening thread to stop
    if (fd_stop_write >= 0) {
        tr_debug("stop_listening() - signaling listener");
        ssize_t s = write(fd_stop_write, "\0", 1);
        (void)s;
        close(fd_stop_write);
        fd_stop_write = -1;
    }

    sem_post(&socket_event_handled);
    pthread_join(socket_listener_thread, NULL);

    if(_security_impl) {
        _security_impl->reset();
    }

}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{

    ssize_t sent_len;

    if(!_running)
    {
        return (-1);
    }

    tr_debug("send_to_socket len - %d", (int)len);

    sent_len = sendto(_socket, buf, len, 0, (const sockaddr*)&_socket_address, _socket_address_len);

    return sent_len;

}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    ssize_t recv_len;

    tr_debug("receive_from_socket");

    if(!_running)
    {
        return (-1);
    }

    if(is_tcp_connection()) {
        recv_len = recv(_socket, buf, len, 0);
    } else {
        struct sockaddr_storage from;
        socklen_t length;
        recv_len = recvfrom(_socket, buf, len, 0, (sockaddr*)&from, &length);
    }

    if(recv_len != -1){
        return recv_len;
    }
    else if(errno == EWOULDBLOCK){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }
    else
    {
        tr_info("Socket returned: %d", (int)recv_len);
    }

    return (-1);
}

void M2MConnectionHandlerPimpl::handle_connection_error(int error)
{
    tr_debug("handle_connection_error");
    _observer.socket_error(error);
}

void M2MConnectionHandlerPimpl::set_platform_network_handler(void *handler)
{

}

void M2MConnectionHandlerPimpl::receive_handshake_handler()
{
    tr_debug("receive_handshake_handler()");
    if( _is_handshaking ){
        int ret = _security_impl->continue_connecting();
        tr_debug("ret %d", ret);
        if( ret == M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ ){ //We wait for next readable event
            tr_debug("We wait for next readable event");
            return;
        } else if( ret == 0 ){
            _is_handshaking = false;
            _use_secure_connection = true;
            enable_keepalive();
            _observer.address_ready(_address,
                                    _server_type,
                                    _server_port);
        }else if( ret < 0 ){
            _is_handshaking = false;
            _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, true);
            close_socket();
        }
    }
}

bool M2MConnectionHandlerPimpl::is_handshake_ongoing()
{
    return _is_handshaking;
}


void M2MConnectionHandlerPimpl::receive_handler()
{
    tr_debug("receive_handler()");

    if(_is_handshaking){
        receive_handshake_handler();
        return;
    }

    if(!_listening || !_running) {
        return;
    }

    if( _use_secure_connection ){

        int rcv_size;

        do{

            rcv_size = _security_impl->read(_recv_buffer, sizeof(_recv_buffer));

            if(rcv_size > 0){

                _observer.data_available((uint8_t*)_recv_buffer,
                                         rcv_size, _address);

            } else if (M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ != rcv_size && rcv_size < 0) {

                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                close_socket();
                return;

            }

        }while(M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ != rcv_size);

    }else{

        ssize_t recv_size;

        do{

            recv_size = recv(_socket, _recv_buffer, sizeof(_recv_buffer), 0);

            if(recv_size == -1 && (errno == EWOULDBLOCK || errno == EINTR)){
                return;
            }
            else if (recv_size <= 0) {

                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                close_socket();
                return;

            }

            tr_debug("data received, len: %zu", recv_size);

            if(!is_tcp_connection()){ // Observer for UDP plain mode

                _observer.data_available((uint8_t*)_recv_buffer, recv_size, _address);

            } else {


                if( recv_size < 4 ){

                    _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                    close_socket();
                    return;

                }

                //We need to "shim" out the length from the front
                uint32_t len = (_recv_buffer[0] << 24 & 0xFF000000) + (_recv_buffer[1] << 16 & 0xFF0000);
                len += (_recv_buffer[2] << 8 & 0xFF00) + (_recv_buffer[3] & 0xFF);

                if(len > 0 && len <= recv_size - 4) {

                    // Observer for TCP plain mode
                    _observer.data_available(_recv_buffer + 4, len, _address);

                }

            }

        }while(recv_size != EWOULDBLOCK);

    }

}

void M2MConnectionHandlerPimpl::claim_mutex()
{
    eventOS_scheduler_mutex_wait();
}

void M2MConnectionHandlerPimpl::release_mutex()
{
    eventOS_scheduler_mutex_release();
}

bool M2MConnectionHandlerPimpl::init_socket()
{
    tr_debug("init_socket - IN");
    _is_handshaking = false;
    _running = true;
    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;
    int status;
    int domain;
    struct sockaddr_storage bind_address = {0};

    if(is_tcp_connection())
    {
        socket_type = SOCK_STREAM;
        socket_protocol = IPPROTO_TCP;
    }

    if(_network_stack == M2MInterface::LwIP_IPv4){
        domain = AF_INET;
    }else if(_network_stack == M2MInterface::LwIP_IPv6){
        domain = AF_INET6;
    }

    tr_debug("init_socket - port %d", _listen_port);

    _socket = socket(domain, socket_type | O_NONBLOCK, socket_protocol);

    if(_socket == -1) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return false;
    }

    if(_network_stack == M2MInterface::LwIP_IPv4){
        struct sockaddr_in* sin = (sockaddr_in*)&bind_address;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(_listen_port);
        memset(&(sin->sin_addr), 0, sizeof(struct in_addr));
    }
    else if(_network_stack == M2MInterface::LwIP_IPv6){
        struct sockaddr_in6* sin6 = (sockaddr_in6*)&bind_address;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(_listen_port);
        memset(&(sin6->sin6_addr), 0, sizeof(struct in6_addr));
    }

    if(_network_stack == M2MInterface::LwIP_IPv4){
        status = bind(_socket, (struct sockaddr *)&bind_address, sizeof(struct sockaddr_in));
    }else if(_network_stack == M2MInterface::LwIP_IPv6){
        status = bind(_socket, (struct sockaddr *)&bind_address, sizeof(struct sockaddr_in6));
    }

    if(status == -1) {
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return false;
    }

    tr_debug("init_socket - OUT");
    return true;
}

bool M2MConnectionHandlerPimpl::is_tcp_connection()
{
    return ( _binding_mode == M2MInterface::TCP ||
             _binding_mode == M2MInterface::TCP_QUEUE );
}

void M2MConnectionHandlerPimpl::close_socket()
{
    tr_debug("close_socket() - IN");
    if(_running) {
       _running = false;
       shutdown(_socket, SHUT_RDWR);
       close(_socket);
    }
    tr_debug("close_socket() - OUT");
}

void M2MConnectionHandlerPimpl::enable_keepalive()
{
#if MBED_CLIENT_TCP_KEEPALIVE_TIME
    if(is_tcp_connection()) {

        int keepalive = MBED_CLIENT_TCP_KEEPALIVE_TIME;
        int enable = 1;
        tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - keepalive %d s\n", keepalive);
        if(setsockopt(_socket,
                      SOL_SOCKET,
                      SO_KEEPALIVE,
                      &enable,
                      sizeof(enable)) != 0) {
            tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive\n");
        }
        if(setsockopt(_socket,
                      SOL_TCP,
                      TCP_KEEPIDLE,
                      &keepalive,
                      sizeof(keepalive)) != 0) {
            tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive Time\n");
        }
        if(setsockopt(_socket,
                      SOL_TCP,
                      TCP_KEEPINTVL,
                      &keepalive,
                      sizeof(keepalive)) != 0) {
            tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive TimeInterval\n");
        }

    }
#endif
}

