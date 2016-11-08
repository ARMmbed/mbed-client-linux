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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <pthread.h>
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

typedef struct {
    void* data_ptr;
    M2MConnectionHandlerPimpl* connection_handler;
} SendEventData_s;

void* __listener_thread(void* arg)
{
    assert(arg != NULL);
    M2MConnectionHandlerPimpl* connection_handler = static_cast<M2MConnectionHandlerPimpl*>(arg);
    if (connection_handler) {
        connection_handler->socket_listener();
    }
    return 0;
}

extern "C" void connection_event_handler(arm_event_s* event)
{
    /*
     * The connection handler instance is passed in differently depending on event type, so we need to
     * first find out which event we're dealing with and then cast data_ptr to correct type to get to
     * the connection handler instance. In any case, if event->data_ptr is null, there is nothing we can do
     */
    if (!event->data_ptr) {
        return;
    }

    M2MConnectionHandlerPimpl* connection_handler = NULL;
    SendEventData_s* send_event_data = NULL;

    switch(event->event_type){

        case M2MConnectionHandlerPimpl::ESocketReadytoRead:
            connection_handler = static_cast<M2MConnectionHandlerPimpl*>(event->data_ptr);
            if (connection_handler) {
                connection_handler->receive_handler();
                connection_handler->signal_socket_event_handled();
            }
            break;

        case M2MConnectionHandlerPimpl::ESocketSend:
            // In this case the data_ptr points to SendEventData_s struct which holds our pointer to connection handler
            // and pointer to the data buffer. The event->event_data field contains the data length
            send_event_data = static_cast<SendEventData_s*>(event->data_ptr);
            if (!send_event_data || !send_event_data->data_ptr) {
                break;
            }

            if (send_event_data->connection_handler) {
                send_event_data->connection_handler->send_socket_data((uint8_t*)send_event_data->data_ptr, event->event_data);
                free(send_event_data->data_ptr);
            }

            free(event->data_ptr);
            break;

        case M2MConnectionHandlerPimpl::ESocketDnsHandler:
            connection_handler = static_cast<M2MConnectionHandlerPimpl*>(event->data_ptr);
            if (connection_handler) {
                connection_handler->dns_handler();
            }
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
    event.data_ptr = this;
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
 _socket_address_len(0),
 _socket_state(ESocketStateDisconnected)
{

    memset(&_address, 0, sizeof _address);
    memset(&_socket_address, 0, sizeof(struct sockaddr_storage));

    int err = sem_init(&_socket_event_handled, 0, 1);
    assert(err == 0);

    eventOS_scheduler_mutex_wait();
    if (M2MConnectionHandlerPimpl::_tasklet_id == -1) {
        M2MConnectionHandlerPimpl::_tasklet_id = eventOS_event_handler_create(&connection_event_handler, ESocketIdle);
        tr_info("M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl() - Tasklet created, id = %d", M2MConnectionHandlerPimpl::_tasklet_id);
    }
    eventOS_scheduler_mutex_release();

}

void M2MConnectionHandlerPimpl::socket_listener()
{
    tr_debug("socket_listener() - started id = %p", (void*)pthread_self());
    // Check if there is a socket for us to listen
    if (_socket < 0) {
        tr_error("socket_listener() - no socket!");
        return;
    }

    fd_set sock_set;
    // Check if we are in connecting state, if so wait until socket becomes writable
    // and update socket state
    while (_running && _socket >= 0 && _socket_state == ESocketStateConnecting) {
        FD_ZERO(&sock_set);
        // Add socket to read set
        FD_SET(_socket, &sock_set);
        if (select(_socket + 1, NULL, &sock_set, NULL, NULL) == -1) {
            tr_error("socket_listener() - write select fail!");
            return;
        }

        if (FD_ISSET(_socket, &sock_set)) {
            _socket_state = ESocketStateConnected;
            send_dns_event();
            break;
        }
    }

    // Ready to listen until we're told not to
    while (_running && _socket >= 0) {
        FD_ZERO(&sock_set);
        // Add socket to read set
        FD_SET(_socket, &sock_set);
        if (select(_socket + 1, &sock_set, NULL, NULL, NULL) == -1) {
            tr_error("socket_listener() - read select fail!");
            return;
        }

        if (FD_ISSET(_socket, &sock_set)) {
            // Socket is ready to read, signal connection handler to read socket
            send_receive_event();
            sem_wait(&_socket_event_handled);
        }
    }
    tr_debug("M2MConnectionHandlerPimpl - listener finished, id = %p", (void*)pthread_self());
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    tr_debug("~M2MConnectionHandlerPimpl() - IN");
    stop_listening();
    sem_destroy(&_socket_event_handled);

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
    tr_debug("resolve_server_address()");

    _security = security;
    _server_port = server_port;
    _server_type = server_type;
    _server_address = server_address;

    return send_dns_event();

}

bool M2MConnectionHandlerPimpl::send_dns_event()
{
    arm_event_s event;

    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketDnsHandler;
    event.data_ptr = this;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;

    return !eventOS_event_send(&event);
}

void M2MConnectionHandlerPimpl::dns_handler()
{
    bool success = false;
    bool retry = false;
    int status = 0;
    int error = 0;
    tr_debug("M2MConnectionHandlerPimpl::dns_handler - IN");

    switch(_socket_state) {
        case ESocketStateDisconnected:
            success = resolve_address();

            if (!success) {
                tr_error("M2MConnectionHandlerPimpl::dns_handler - No connection");
                close_socket();
                _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT, retry);
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
                return;
            }

            _running = true;
            if (!setup_listener_thread()) {
                _running = false;
                close_socket();
                _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT, retry);
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - listener thread error %s");
                return;
            }

            if (_socket_state == ESocketStateConnected) {
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - connected, sending new event for security");
                // Connect was synchronous and successful, so schedule new DNS event to continue the connection.
                // i.e. Execute next case, this should probably be just a call to function without unnecessary event
                if (!send_dns_event()) {
                    tr_debug("M2MConnectionHandlerPimpl::dns_handler - couldn't send event");
                    _running = false;
                    close_socket();
                    _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT, retry);
                    return;
                }
            }
            break;
        case ESocketStateConnected:
            if (_security) {
                if (_security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
                    _security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk) {

                    if( _security_impl != NULL ){
                        _security_impl->reset();
                        if (_security_impl->init(_security) == 0) {
                            _is_handshaking = true;
                            success = true;
                            tr_debug("dns_handler - connect DTLS");
                            if(_security_impl->start_connecting_non_blocking(_base) < 0 ){
                                tr_debug("dns_handler - handshake failed");
                                _is_handshaking = false;
                                success = false;
                                retry = true;
                            }
                        } else {
                            tr_error("dns_handler - init failed");
                            success = false;
                            retry = false;
                        }
                    } else {
                        tr_error("dns_handler - sec is null");
                        success = false;
                        retry = false;
                    }

                    if (!success) {
                        close_socket();
                        _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, retry);
                        tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
                        return;
                    }
                }

            }
            if(!_is_handshaking) {
                tr_debug("M2MConnectionHandlerPimpl::dns_handler - address_ready");
                enable_keepalive();
                _observer.address_ready(_address,
                                        _server_type,
                                        _address._port);
            }
            break;
        case ESocketStateConnecting:
        default:
            // Nothing for us to do here?
            break;
    }
    tr_debug("M2MConnectionHandlerPimpl::dns_handler - OUT");
}

bool M2MConnectionHandlerPimpl::resolve_address()
{
    struct addrinfo _hints;
    struct addrinfo *addr_info = NULL;
    struct addrinfo *addr_info_iter = NULL;
    bool success = false;
    bool retry = false;
    int status = 0;
    int error = 0;

    _hints = build_address_hints();

    status = getaddrinfo(_server_address.c_str(), NULL, &_hints, &addr_info);
    if (status == 0 && addr_info) {
        char ip_address[INET6_ADDRSTRLEN];
        addr_info_iter = addr_info;
        while(addr_info_iter) {
            tr_debug("M2MConnectionHandlerPimpl::resolve_address() - new address");
            close_socket();
            if(!init_socket()) {
                tr_debug("M2MConnectionHandlerPimpl::resolve_address() - init socket fail");
                retry = true;
                break;
            }
            // Load socket address from result entry
            memset(&_socket_address, 0, sizeof(struct sockaddr_storage));
            memcpy(&_socket_address, addr_info_iter->ai_addr, addr_info_iter->ai_addrlen);
            // Store length
            _socket_address_len = addr_info_iter->ai_addrlen;
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
                    tr_debug("M2MConnectionHandlerPimpl::resolve_address() - connecting to %s\n", ip_address);
                    success = connect_socket();
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
                    tr_debug("M2MConnectionHandlerPimpl::resolve_address() - connecting to %s\n", ip_address);
                    success = connect_socket();
                    break;
                }
            }
            if (success) {
                break; // Working connection found, exit from loop
            }
            addr_info_iter = addr_info_iter->ai_next;
        }
    }

    freeaddrinfo(addr_info);

    return success;
}

struct addrinfo M2MConnectionHandlerPimpl::build_address_hints()
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    if(_network_stack == M2MInterface::LwIP_IPv4 ||
       _network_stack == M2MInterface::ATWINC_IPv4) {
        hints.ai_family = AF_INET;
    }
    else if (_network_stack == M2MInterface::LwIP_IPv6 ||
            _network_stack == M2MInterface::Nanostack_IPv6) {
        hints.ai_family = AF_INET6;
    }
    else {
        hints.ai_family = AF_UNSPEC;
    }

    if (is_tcp_connection()) {
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }
    else {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    return hints;
}

bool M2MConnectionHandlerPimpl::connect_socket()
{
    int status = -1;
    bool success = false;
    status = connect(_socket, (const struct sockaddr *)&_socket_address, _socket_address_len);
    int error = errno;
    if (status == 0) {
        success = true;
        _socket_state = ESocketStateConnected;
        tr_debug("M2MConnectionHandlerPimpl::connect_socket() - connected");
    }
    else if (error == EINPROGRESS) {
        success = true;
        _socket_state = ESocketStateConnecting;
        tr_debug("M2MConnectionHandlerPimpl::connect_socket() - connecting asynchronous");
    } else {
        success = false;
        tr_error("M2MConnectionHandlerPimpl::connect_socket() - failed to connect, reason %s", strerror(error));
    }
    return success;
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

    SendEventData_s* event_data = (SendEventData_s*)malloc(sizeof(SendEventData_s));
    if (!event_data) {
        return false;
    }

    event_data->data_ptr = (uint8_t*)malloc(data_len);
    if(!event_data->data_ptr) {
        free(event_data);
        return false;
    }
    memcpy(event_data->data_ptr, data, data_len);
    event_data->connection_handler = this;

    event.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event.sender = 0;
    event.event_type = ESocketSend;
    event.event_data = data_len;
    event.data_ptr = event_data;
    event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;

    if (eventOS_event_send(&event) != 0) {
        // Event push failed, free the buffer
        free(event_data->data_ptr);
        free(event_data);
        return false;
    }

    return true;

}

void M2MConnectionHandlerPimpl::send_socket_data(uint8_t *data, uint16_t data_len)
{

    ssize_t sent_len;
    bool success = false;
    int error = 0;

    if(!data || !data_len || !_running)
    {
        tr_debug("send_handler() - fail, data = %p, data_len = %d, _running = %d", data, data_len, _running);
        return;
    }


    tr_debug("send_handler() - IN");

    if( _use_secure_connection ){
        if( _security_impl->send_message(data, data_len) > 0){
            success = true;
        }
    } else {

        tr_debug("send_handler() - sending to socket=%d", _socket);
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
        close_socket();
        tr_error("M2MConnectionHandlerPimpl::send_socket_data - sendto error: %s", strerror(error));
        _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR, true);
    }
    else{
        _observer.data_sent();
    }


}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{

    tr_debug("start_listening_for_data()");

    _listening = true;

    return true;

}

void M2MConnectionHandlerPimpl::stop_listening()
{

    if (_running) {
        tr_debug("stop_listening() - thread id = %p", _socket_listener_thread);

        _listening = false;

        pthread_cancel(_socket_listener_thread);
        pthread_join(_socket_listener_thread, NULL);
        _running = false;
    }

    // Close the socket
    close_socket();

    // Reset security
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

    tr_debug("receive_from_socket - running=%d, _socket=%d, buf=%d, len=%d", _running, _socket, buf, len);

    if(!_running)
    {
        return (-1);
    }

    if(is_tcp_connection()) {
        recv_len = recv(_socket, buf, len, 0);
    } else {
        struct sockaddr_storage from;
        socklen_t length = sizeof(struct sockaddr_storage);
        recv_len = recvfrom(_socket, buf, len, 0, (sockaddr*)&from, &length);
    }

    int error = errno;
    tr_debug("receive_from_socket - recv_len=%d, error=%s", recv_len, strerror(error));
    if(recv_len != -1){
        return recv_len;
    }
    else if(error == EWOULDBLOCK){
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
    (void)handler;
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
            close_socket();
            _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, true);
        }
    }
}

bool M2MConnectionHandlerPimpl::is_handshake_ongoing()
{
    return _is_handshaking;
}


void M2MConnectionHandlerPimpl::receive_handler()
{
    tr_debug("receive_handler() - _is_handshaking=%d, _listening=%d, _running=%d, _use_secure_connection=%d", _is_handshaking, _listening, _running, _use_secure_connection);

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

                close_socket();
                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
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

                close_socket();
                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                return;

            }

            tr_debug("data received, len: %zu", recv_size);

            if(!is_tcp_connection()){ // Observer for UDP plain mode

                _observer.data_available((uint8_t*)_recv_buffer, recv_size, _address);

            } else {


                if( recv_size < 4 ){

                    close_socket();
                    _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
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
    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;
    int status;
    int domain;
    struct sockaddr_storage bind_address;
    memset(&bind_address, 0, sizeof(struct sockaddr_storage));

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
    tr_debug("init_socket - domain %d, type %d, proto %d", domain, socket_type, socket_protocol);

    _socket = socket(domain, socket_type | O_NONBLOCK, socket_protocol);

    if(_socket == -1) {
        tr_debug("init_socket - socket fail");
        return false;
    }

    if(_network_stack == M2MInterface::LwIP_IPv4){
        struct sockaddr_in* sin = (sockaddr_in*)&bind_address;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(_listen_port);
        sin->sin_addr.s_addr = INADDR_ANY;
    }
    else if(_network_stack == M2MInterface::LwIP_IPv6){
        struct sockaddr_in6* sin6 = (sockaddr_in6*)&bind_address;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(_listen_port);
        sin6->sin6_addr = in6addr_any;
    }

    if(_network_stack == M2MInterface::LwIP_IPv4){
        status = bind(_socket, (struct sockaddr *)&bind_address, sizeof(struct sockaddr_in));
    }else if(_network_stack == M2MInterface::LwIP_IPv6){
        status = bind(_socket, (struct sockaddr *)&bind_address, sizeof(struct sockaddr_in6));
    }

    if(status == -1) {
        tr_debug("init_socket - bind fail");
        return false;
    }
    tr_debug("init_socket - socket=%d", _socket);
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
    if(_running && _socket >= 0) {
       _running = false;
       shutdown(_socket, SHUT_RDWR);
       close(_socket);
       _socket = -1;
       _socket_state = ESocketStateDisconnected;
    }
    tr_debug("close_socket() - OUT");
}

bool M2MConnectionHandlerPimpl::setup_listener_thread()
{
    int error = pthread_create(&_socket_listener_thread, NULL,__listener_thread, (void*)this);
    if (error == 0) {
        return true;
    }

    tr_error("M2MConnectionHandlerPimpl::setup_listener_thread() - couldn't create thread, error %d", error);
    return false;
}

void M2MConnectionHandlerPimpl::signal_socket_event_handled(void)
{
    sem_post(&_socket_event_handled);
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

