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
#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "mbed-client-linux/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "include/connthreadhelper.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconfig.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity *sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _binding_mode(mode),
 _stack(stack),
 _socket_server(-1),
 _slen_sa_dst(sizeof(_sa_dst)),
 _slen_sa_dst6(sizeof(_sa_dst6)),
 _listen_thread(0),
 _receive_data(false),
 _listen_port(0)
{
    __connection_impl = this;
    _received_packet_address = (M2MConnectionObserver::SocketAddress *)malloc(sizeof(M2MConnectionObserver::SocketAddress));
    if(_received_packet_address) {
        memset(_received_packet_address, 0, sizeof(M2MConnectionObserver::SocketAddress));
        _received_packet_address->_address = _received_address;
    }
    memset(&(_sa_dst), 0, sizeof(sockaddr_in));
    memset(&(_sa_src), 0, sizeof(sockaddr_in));
    memset(&(_sa_dst6), 0, sizeof(sockaddr_in6));
    memset(&(_sa_src6), 0, sizeof(sockaddr_in6));
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    if(_received_packet_address) {
        free(_received_packet_address);
        _received_packet_address = NULL;
    }

    if(_socket_server > 0) {
        close(_socket_server);
        _socket_server = -1;
    }

    if(_listen_thread > 0) {
        if (!pthread_equal(_listen_thread, pthread_self())) {
            pthread_detach(_listen_thread);
        }
    }

    __connection_impl = NULL;
    delete _security_impl;
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
    tr_debug("M2MConnectionHandlerPimpl::resolve_server_address");
    M2MConnectionHandler::ConnectionError error = M2MConnectionHandler::ERROR_NONE;
    bool retry = true;
    /* Resolve hostname of NSP */
    if (resolve_hostname(server_address.c_str(), server_port)) {
        if( security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk ){
            tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - secure");
            if( _security_impl != NULL ){
                _security_impl->reset();
                if (_security_impl->init(security) == 0) {
                    int ret = -1;
                    int retry_count = 0;
                    do {
                        ret = _security_impl->connect(_base);
                        if (ret == -1 && !is_tcp_connection()) {
                            tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - retry handshake");
                            _security_impl->reset();
                            _security_impl->init(security);
                            retry_count++;
                        } else {
                            break;
                        }
                    } while (retry_count <= MBED_CLIENT_RECONNECTION_COUNT);

                    if (ret == 0) {
                        _use_secure_connection = true;
                    } else {
                        tr_error("M2MConnectionHandlerPimpl::resolve_server_address - hanshake failed");
                        _security_impl->reset();
                        error = M2MConnectionHandler::SSL_CONNECTION_ERROR;
                    }
                } else {
                    tr_error("M2MConnectionHandlerPimpl::resolve_server_address - init failed");
                    error = M2MConnectionHandler::SSL_CONNECTION_ERROR;
                    retry = false;
                }
            } else {
                tr_error("M2MConnectionHandlerPimpl::resolve_server_address - sec is null");
                error = M2MConnectionHandler::SSL_CONNECTION_ERROR;
                retry = false;
            }
        }
    }
    else {
        tr_error("M2MConnectionHandlerPimpl::resolve_server_address - DNS resolving fails");
        error = M2MConnectionHandler::DNS_RESOLVING_ERROR;
    }

    if (error != M2MConnectionHandler::ERROR_NONE) {
        _observer.socket_error(error, retry);
        return false;
    }
    else {
        _observer.address_ready(*_received_packet_address,server_type, server_port);
        return true;
    }
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    tr_debug("M2MConnectionHandlerPimpl::start_listening_for_data()");
    bool success = true;
    if(!_receive_data) {
        _receive_data = true;
        pthread_create(&_listen_thread, NULL,__listen_data_function, this);
    }
    return success;
}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    if (_stack == M2MInterface::LwIP_IPv4) {
        return sendto(_socket_server, (char*)buf, len, 0,
                      (const struct sockaddr *)&_sa_dst, _slen_sa_dst);
    }
    else if(_stack == M2MInterface::LwIP_IPv6) {
        _sa_dst6.sin6_scope_id = 0;
        return sendto(_socket_server, (char*)buf, len, 0,
                      (const struct sockaddr *)&_sa_dst6, _slen_sa_dst6);
    }
    else {
        return -1;
    }
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    int ret = 0;
    if (_stack == M2MInterface::LwIP_IPv4) {
        do {
            ret = recvfrom(_socket_server, buf,
                                         len, 0, (struct sockaddr *)&_sa_dst,
                                         (socklen_t*)&_slen_sa_dst);
        }
        while(ret == -1 && errno == EINTR);
        return ret;
    }

    else if(_stack == M2MInterface::LwIP_IPv6) {
        do {
            ret = recvfrom(_socket_server, buf,
                                         len, 0, (struct sockaddr *)&_sa_dst6,
                                         (socklen_t*)&_slen_sa_dst6);
        }
        while(ret == -1 && errno == EINTR);
        return ret;
    }
    else {
        return -1;
    }
}

void M2MConnectionHandlerPimpl::data_receive(void *object)
{
    tr_debug("M2MConnectionHandlerPimpl::data_receive");
    if(object != NULL){
        M2MConnectionHandlerPimpl *thread_object = static_cast<M2MConnectionHandlerPimpl*> (object);
        if(thread_object) {
            pthread_join(_listen_thread, NULL);
        }
        int16_t rcv_size = -1;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(_socket_server, &read_fds);
        timeval timeout = { 5, 0 }; // 5 seconds
        select(_socket_server + 1, &read_fds, NULL, NULL, &timeout);
        memset(_received_buffer, 0, BUFFER_LENGTH);
        if( _use_secure_connection ){
            while (_receive_data) {
                if (FD_ISSET(_socket_server, &read_fds)) {
                    int rcv_size = _security_impl->read(_received_buffer, BUFFER_LENGTH);
                    tr_debug("M2MConnectionHandlerPimpl::data_receive - rcv_size %d", rcv_size);
                    if(rcv_size > 0){
                        if (_stack == M2MInterface::LwIP_IPv4) {
                            _received_packet_address->_port = ntohs(_sa_dst.sin_port);
                        }
                        else if (_stack == M2MInterface::LwIP_IPv6) {
                            _received_packet_address->_port = ntohs(_sa_dst6.sin6_port);
                        }
                        _observer.data_available(_received_buffer, rcv_size, *_received_packet_address);
                    }
                    // EOF received or some negative error code
                    else{
                        tr_error("M2MConnectionHandlerPimpl::data_receive - secure error: %s", strerror(errno));
                        _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR);
                        _receive_data = false;
                    }
                    memset(_received_buffer, 0, BUFFER_LENGTH);
                } else {
                    _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR);
                    _receive_data = false;
                }
           }
        }else{
            while(_receive_data) {
                char rcv_in_addr[INET6_ADDRSTRLEN];
                memset(rcv_in_addr,0,INET6_ADDRSTRLEN);
                if (FD_ISSET(_socket_server, &read_fds)) {
                    switch (_stack) {
                    case M2MInterface::LwIP_IPv4:
                        do {
                            rcv_size=recvfrom(_socket_server, _received_buffer,
                                          BUFFER_LENGTH, 0, (struct sockaddr *)&_sa_dst,
                                          (socklen_t*)&_slen_sa_dst);
                        }
                        while(rcv_size == -1 && errno == EINTR);

                        inet_ntop(AF_INET, &(_sa_dst.sin_addr),rcv_in_addr,INET_ADDRSTRLEN);
                        if (rcv_size > 0) {
                            if(_received_packet_address) {
                                _received_packet_address->_port = ntohs(_sa_dst.sin_port);
                                memcpy(_received_packet_address->_address, &_sa_dst.sin_addr, 4);
                                _received_packet_address->_stack = _stack;
                                _received_packet_address->_length = 4;
                            }
                        }
                        break;
                    case M2MInterface::LwIP_IPv6:
                        do {
                            rcv_size=recvfrom(_socket_server, _received_buffer,
                                          BUFFER_LENGTH, 0, (struct sockaddr *)&_sa_dst6,
                                          (socklen_t*)&_slen_sa_dst6);
                        }
                        while(rcv_size == -1 && errno == EINTR);

                        if (rcv_size > 0) {
                            inet_ntop(AF_INET6,
                                      &(_sa_dst6.sin6_addr),
                                      rcv_in_addr,
                                      INET6_ADDRSTRLEN);
                        }
                        if(_received_packet_address) {
                            _received_packet_address->_port = ntohs(_sa_dst6.sin6_port);
                            memcpy(_received_packet_address->_address,
                                   &_sa_dst6.sin6_addr,
                                   sizeof(_sa_dst6.sin6_addr));
                            _received_packet_address->_stack = _stack;
                            _received_packet_address->_length = sizeof(_sa_dst6.sin6_addr);
                        }
                        break;
                    default:
                        break;
                    }
                }

                if (rcv_size == -1) {
                    tr_error("M2MConnectionHandlerPimpl::data_receive - error: %s", strerror(errno));
                    _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR);
                    _receive_data = false;
                }

                /* If message received.. */
                if(rcv_size > 0 && _received_packet_address) {
                    if(is_tcp_connection()){
                        //We need to "shim" out the length from the front
                        if( rcv_size > 4 ){
                            uint64_t len = (_received_buffer[0] << 24 & 0xFF000000) + (_received_buffer[1] << 16 & 0xFF0000);
                            len += (_received_buffer[2] << 8 & 0xFF00) + (_received_buffer[3] & 0xFF);
                            uint8_t* buf = (uint8_t*)malloc(len);
                            memmove(buf, _received_buffer+4, len);
                            _observer.data_available(buf, len, *_received_packet_address);
                            free(buf);
                        }else{
                            _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR);
                            _receive_data = false;
                        }
                    }else{
                        _observer.data_available(_received_buffer,rcv_size,*_received_packet_address);
                    }
                }
                memset(_received_buffer, 0, BUFFER_LENGTH);
            }
        }
    }
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    tr_debug("M2MConnectionHandlerPimpl::send_data");
    bool success = false;
    if(data){
        if( _use_secure_connection ){
            if( _security_impl->send_message(data, data_len) > 0){
                success = true;
                _observer.data_sent();
            }else{
                tr_error("M2MConnectionHandlerPimpl::send_data - secure error: %s", strerror(errno));
                _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR);
            }
        }else{
            if(address) {
                switch (_stack) {
                    case M2MInterface::LwIP_IPv4:
                        _sa_dst.sin_family = AF_INET;
                        _sa_dst.sin_port = htons(address->port);
                        memcpy(&_sa_dst.sin_addr, address->addr_ptr, address->addr_len);
                        break;
                    case M2MInterface::LwIP_IPv6:
                        _sa_dst6.sin6_family = AF_INET6;
                        _sa_dst6.sin6_port = htons(address->port);
                        memcpy(&_sa_dst6.sin6_addr, address->addr_ptr, address->addr_len);
                        break;
                    default:
                        break;
                    }

                ssize_t ret = -1;
                if(is_tcp_connection()){
                    //We need to "shim" the length in front
                    uint16_t d_len = data_len+4;
                    uint8_t* d = (uint8_t*)malloc(data_len+4);

                    d[0] = (data_len >> 24 )& 0xff;
                    d[1] = (data_len >> 16 )& 0xff;
                    d[2] = (data_len >> 8 )& 0xff;
                    d[3] = data_len & 0xff;
                    memmove(d+4, data, data_len);
                    ret = sendto(_socket_server, d, d_len, MSG_NOSIGNAL, (const struct sockaddr *)&_sa_dst, sizeof(sockaddr_in));
                    free(d);
                }else{
                    if (_stack == M2MInterface::LwIP_IPv4) {
                        ret = sendto(_socket_server, data, data_len, 0, (const struct sockaddr *)&_sa_dst, sizeof(sockaddr_in));
                    }
                    else if (_stack == M2MInterface::LwIP_IPv6) {
                        ret = sendto(_socket_server, data, data_len, 0, (const struct sockaddr *)&_sa_dst6, sizeof(sockaddr_in6));
                    }
                    //else ret == -1
                }

                if (ret == -1) {
                    tr_error("M2MConnectionHandlerPimpl::send_data - error: %s", strerror(errno));
                    _receive_data = false;
                    _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR);
                } else {
                     success = true;
                    _observer.data_sent();
                }
            } else {
                tr_error("M2MConnectionHandlerPimpl::send_data - addr is null");
                _observer.socket_error(M2MConnectionHandler::SOCKET_SEND_ERROR);
                _receive_data = false;
            }
        }
    }
    return success;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    tr_debug("M2MConnectionHandlerPimpl::stop_listening()");
    _receive_data = false;
}

void M2MConnectionHandlerPimpl::handle_connection_error(int error)
{
    _observer.socket_error(error);
}

bool M2MConnectionHandlerPimpl::resolve_hostname(const char *address,
                                                 const uint16_t server_port)
{
    tr_debug("M2MConnectionHandlerPimpl::resolve_hostname");
    _slen_sa_dst = sizeof(_sa_dst);
    _slen_sa_dst6 = sizeof(_sa_dst6);
    bool success = false;
    struct addrinfo *addr_info = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    if (_stack == M2MInterface::LwIP_IPv4) {
        hints.ai_family = AF_INET;
    }
    else if (_stack == M2MInterface::LwIP_IPv6 ||
             _stack == M2MInterface::Nanostack_IPv6) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = AF_UNSPEC;
    }

    if(_socket_server > 0) {
        close(_socket_server);
        _socket_server = -1;
    }
    create_socket();
    if (_socket_server != -1) {
        success = true;
    }
    // If listen port is something else than default then use it otherwise randomize
    if (_listen_port != 5683 && success) {
        success = false;
        if (bind_socket() != -1) {
            success = true;
        } else {
            tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - binding fails, %s", strerror(errno));
        }
    }

    if (success && _received_packet_address) {
        success = false;
        int r = getaddrinfo(address, NULL, &hints, &addr_info);
        if (r == 0 && addr_info) {
            struct sockaddr_in *a = NULL;
            struct sockaddr_in6 *a6 = NULL;

            char ip_address[INET6_ADDRSTRLEN];
            while(addr_info) {
                switch(addr_info->ai_family) {
                    case AF_INET:
                        a = (struct sockaddr_in*)addr_info->ai_addr;
                        if(a) {
                            inet_ntop(AF_INET,&(a->sin_addr),ip_address,INET_ADDRSTRLEN);
                            inet_pton(AF_INET, ip_address, &_resolved_address);
                            _received_packet_address->_port = server_port;
                            memcpy(_received_packet_address->_address, _resolved_address, 4);
                            _received_packet_address->_stack = M2MInterface::LwIP_IPv4;
                            _received_packet_address->_length = 4;
                            _sa_dst.sin_family = AF_INET;
                            _sa_dst.sin_port = ntohs(server_port);
                            memcpy(&_sa_dst.sin_addr, _received_packet_address->_address, _received_packet_address->_length);
                            if (connect(_socket_server, (const struct sockaddr *)&_sa_dst, _slen_sa_dst) != 0) {
                                success = false;
                                tr_error("M2MConnectionHandlerPimpl::resolve_hostname - failed to connect %s, %s", ip_address, strerror(errno));
                            } else {
                                success = true;
                                tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - connected to %s\n", ip_address);
                            }
                        }
                        break;
                    case AF_INET6:
                        a6 =  (struct sockaddr_in6*)addr_info->ai_addr;
                        if(a6) {
                            inet_ntop(AF_INET6,
                                      &(a6->sin6_addr),
                                      ip_address,
                                      INET6_ADDRSTRLEN);

                            inet_pton(AF_INET6, ip_address, &_resolved_address);
                            _received_packet_address->_port = server_port;
                            memcpy(_received_packet_address->_address,
                                   _resolved_address,
                                   sizeof(_resolved_address));
                            _received_packet_address->_stack = M2MInterface::LwIP_IPv6;
                            _received_packet_address->_length = sizeof(_resolved_address);

                            _sa_dst6.sin6_family = AF_INET6;
                            _sa_dst6.sin6_port = ntohs(server_port);
                            memcpy(&_sa_dst6.sin6_addr,
                                   _received_packet_address->_address,
                                   _received_packet_address->_length);
                            _sa_dst6.sin6_scope_id = 0;
                            if (connect(_socket_server, (const struct sockaddr *)&_sa_dst6, _slen_sa_dst6) != 0) {
                                success = false;
                                tr_error("M2MConnectionHandlerPimpl::resolve_hostname - failed to connect %s\n", ip_address);
                            } else {
                                success = true;
                                tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - connected to %s\n", ip_address);
                            }
                        }
                        break;
                }
                if (success) {
                    break; // Working connection found, exit from loop
                }
                addr_info = addr_info->ai_next;
            }
        }
        freeaddrinfo(addr_info);
    }

    if (success) {
        if(is_tcp_connection()){
#if MBED_CLIENT_TCP_KEEPALIVE_TIME
            int keepalive = MBED_CLIENT_TCP_KEEPALIVE_TIME;
            int enable = 1;
            tr_debug("M2MConnectionHandlerPimpl::resolve_hostname - keepalive %d s\n", keepalive);
            if(setsockopt(_socket_server,
                          SOL_SOCKET,
                          SO_KEEPALIVE,
                          &enable,
                          sizeof(enable)) != 0) {
                tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive\n");
            }
            if(setsockopt(_socket_server,
                          SOL_TCP,
                          TCP_KEEPIDLE,
                          &keepalive,
                          sizeof(keepalive)) != 0) {
                tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive Time\n");
            }
            if(setsockopt(_socket_server,
                          SOL_TCP,
                          TCP_KEEPINTVL,
                          &keepalive,
                          sizeof(keepalive)) != 0) {
                tr_error("M2MConnectionHandlerPimpl::resolve_hostname - setsockopt fail to Set Keepalive TimeInterval\n");
            }
#endif
        }
    }
    return success;
}

void M2MConnectionHandlerPimpl::create_socket() {
    if (_stack == M2MInterface::LwIP_IPv4) {
        if(is_tcp_connection()){
            _socket_server = socket(AF_INET, SOCK_STREAM,
                    IPPROTO_TCP);
        } else {
            _socket_server = socket(AF_INET, SOCK_DGRAM,
                    IPPROTO_UDP);
        }
    }
    else if (_stack == M2MInterface::LwIP_IPv6 ||
             _stack == M2MInterface::Nanostack_IPv6) {
        if(is_tcp_connection()){
            _socket_server = socket(AF_INET6, SOCK_STREAM,
                    IPPROTO_TCP);
        } else {
            _socket_server = socket(AF_INET6, SOCK_DGRAM,
                    IPPROTO_UDP);
        }
    } else {
        _socket_server = -1;
    }
}

int M2MConnectionHandlerPimpl::bind_socket() {
    tr_debug("M2MConnectionHandlerPimpl::bind_socket - port: %d", _listen_port);
    if (_stack == M2MInterface::LwIP_IPv4) {
        memset((char *) &_sa_src, 0, sizeof(_sa_src));
        _sa_src.sin_family = AF_INET;
        _sa_src.sin_port = htons(_listen_port);
        _sa_src.sin_addr.s_addr = INADDR_ANY;
        return bind(_socket_server, (struct sockaddr *) &_sa_src, sizeof(_sa_src));

    }
    else if (_stack == M2MInterface::LwIP_IPv6 ||
             _stack == M2MInterface::Nanostack_IPv6) {
        memset((char *) &_sa_src6, 0, sizeof(_sa_src6));
        _sa_src6.sin6_family = AF_INET6;
        _sa_src6.sin6_port = htons(_listen_port);
        _sa_src6.sin6_addr = in6addr_any;
        return bind(_socket_server, (struct sockaddr *) &_sa_src6, sizeof(_sa_src6));
    }
    else {
        return -1;
    }
}

bool M2MConnectionHandlerPimpl::is_tcp_connection()
{
    return _binding_mode == M2MInterface::TCP ||
            _binding_mode == M2MInterface::TCP_QUEUE ? true : false;
}
