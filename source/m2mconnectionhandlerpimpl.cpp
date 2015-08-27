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
#include "mbed-client-linux/m2mconnectionhandlerpimpl.h"
#include "include/connthreadhelper.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client-libservice/ns_trace.h"

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                   M2MConnectionSecurity *sec,
                                                   M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _stack(M2MInterface::Uninitialized),
 _socket_server(-1),
 _slen_sa_dst(sizeof(_sa_dst)),
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
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    if(_received_packet_address) {
        free(_received_packet_address);
        _received_packet_address = NULL;
    }

    if(_listen_thread > 0) {
        if (!pthread_equal(_listen_thread, pthread_self())) {
            pthread_detach(_listen_thread);
        }
    }
    if(_socket_server > 0) {
        tr_debug("M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl - shutdown server\n");
        shutdown(_socket_server,SHUT_RDWR);
        _socket_server = -1;
    }
    __connection_impl = NULL;

    delete _security_impl;
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    bool success = false;
    if(_listen_port == 0) {
         success = true;
        _listen_port = listen_port;
    }
    return success;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                  const uint16_t server_port,
                                                  M2MConnectionObserver::ServerType server_type,
                                                  const M2MSecurity* security)
{
    bool success = false;
    const char* address = server_address.c_str();

    struct addrinfo *addr = NULL;
    struct sockaddr_in *a = NULL;
    struct sockaddr_in6 *a6 = NULL;
    int family;
    int r;

    /* Resolve hostname of NSP */
    r = getaddrinfo(address, NULL, NULL, &addr);
    if (r == 0 && addr) {
        /* Take the first address and give it to NSDL and EDTLS*/
        family = addr->ai_family;
        switch(family) {
        case AF_INET:
            tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - address is IPv4\n");
            char ip_address[INET_ADDRSTRLEN];
            a = (struct sockaddr_in*)addr->ai_addr;
            if(a) {
                inet_ntop(AF_INET,&(a->sin_addr),ip_address,INET_ADDRSTRLEN);

                if(_socket_server == -1) {
                   _socket_server=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                   bind_socket();
                }

                inet_pton(AF_INET, ip_address, &_resolved_address);

                if(_received_packet_address) {
                    success = true;
                    //Support for IPv4
                    _received_packet_address->_port = ntohs(server_port);
                    memcpy(_received_packet_address->_address, _resolved_address, 4);
                    _received_packet_address->_stack = M2MInterface::LwIP_IPv4;
                    _stack = M2MInterface::LwIP_IPv4;
                    _received_packet_address->_length = 4;
                }
            }
            break;
        case AF_INET6:
            tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - address is IPv6\n");
            char ip6_address[INET6_ADDRSTRLEN];
            a6 =  (struct sockaddr_in6*)addr->ai_addr;
            if(a6) {
                inet_ntop(AF_INET6,&(a6->sin6_addr),ip6_address,INET6_ADDRSTRLEN);
                if(_socket_server == -1) {
                   _socket_server=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                   bind_socket();
                }

                inet_pton(AF_INET6, ip6_address, &_resolved_address);

                if(_received_packet_address) {
                    success = true;
                    //Support for IPv6
                    _received_packet_address->_port = ntohs(server_port);
                    memcpy(_received_packet_address->_address, _resolved_address, 16);
                    _received_packet_address->_stack = M2MInterface::LwIP_IPv6;
                    _stack = M2MInterface::LwIP_IPv6;
                    _received_packet_address->_length = 16;
                }
            }
            break;
        }
        freeaddrinfo(addr);

        _sa_dst.sin_family = AF_INET;
        _sa_dst.sin_port = _received_packet_address->_port;
        memcpy(&_sa_dst.sin_addr, _received_packet_address->_address, _received_packet_address->_length);
        connect((uint)_socket_server, (const struct sockaddr *)&_sa_dst, _slen_sa_dst);

        if( security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk ){
            if( _security_impl != NULL ){
                _security_impl->reset();
                _security_impl->init(security);
                success = 0 == _security_impl->connect(_base);
                if( success ){
                    _use_secure_connection = true;
                }
            }else{
                success = false;
            }
        }

        if(success) {
            _observer.address_ready(*_received_packet_address,server_type,server_port);
        }
    }
    else {
        //TODO: Define memory fail error code
        _observer.socket_error(3);
    }
    return success;
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    bool success = true;
    if(!_receive_data) {
        _receive_data = true;
        pthread_create(&_listen_thread, NULL,__listen_data_function, this);
    }
    return success;
}


int M2MConnectionHandlerPimpl::sendToSocket(const unsigned char *buf, size_t len)
{
    return sendto(_socket_server, (char*)buf, len, 0, (const struct sockaddr *)&_sa_dst, _slen_sa_dst);
}

int M2MConnectionHandlerPimpl::receiveFromSocket(unsigned char *buf, size_t len)
{
    return recvfrom(_socket_server, buf,
                      len, 0, (struct sockaddr *)&_sa_dst,
                      (socklen_t*)&_slen_sa_dst);
}

void M2MConnectionHandlerPimpl::data_receive(void *object)
{
    if(object != NULL){
        M2MConnectionHandlerPimpl *thread_object = (M2MConnectionHandlerPimpl*) object;
        if(thread_object) {
            pthread_join(_listen_thread, NULL);
        }
        int16_t rcv_size=0;
        memset(_received_buffer, 0, 1024);

        if( _use_secure_connection ){
            while(_receive_data){
                int rcv_size = _security_impl->read(_received_buffer, 1024);
                if(rcv_size > 0){
                    _observer.data_available(_received_buffer,rcv_size,*_received_packet_address);
                }else if(rcv_size == 0){
                    //We are in initializing phase, so do nothing
                }else{
                    _receive_data = false;
                    _observer.socket_error(1);
                }
                memset(_received_buffer, 0, 1024);
            }
        }else{
            while(_receive_data) {
                char rcv_in_addr[256];
                memset(rcv_in_addr,0,256);
                rcv_size=recvfrom(_socket_server, _received_buffer,
                                  1024, 0, (struct sockaddr *)&_sa_dst,
                                  (socklen_t*)&_slen_sa_dst);
                if (rcv_size == -1) {
                   //TODO: Define receive error code
                    _observer.socket_error(2);
                    _receive_data = false;
                } else {
                    inet_ntop(AF_INET, &(_sa_dst.sin_addr),rcv_in_addr,INET_ADDRSTRLEN);
                    if(_received_packet_address) {
                        _received_packet_address->_port = ntohs(_sa_dst.sin_port);
                        memcpy(_received_packet_address->_address, &_sa_dst.sin_addr, 4);
                        _received_packet_address->_stack = _stack;
                        _received_packet_address->_length = 4;
                    }
                }
                /* If message received.. */
                if(rcv_size > 0 && _received_packet_address) {
                    _observer.data_available(_received_buffer,rcv_size,*_received_packet_address);
                }
                memset(_received_buffer, 0, 1024);
            }
        }
    }
}

void M2MConnectionHandlerPimpl::bind_socket()
{
    memset((char *) &_sa_src, 0, sizeof(_sa_src));
    _sa_src.sin_family = AF_INET;
    _sa_src.sin_port = htons(_listen_port);

    /* Listen to the port */
    _sa_src.sin_addr.s_addr = INADDR_ANY;
    bind(_socket_server, (struct sockaddr *) &_sa_src, sizeof(_sa_src));
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    bool success = false;
    if( _use_secure_connection ){
        if( _security_impl->send_message(data, data_len) > 0){
            success = true;
            _observer.data_sent();
        }else{
            _observer.socket_error(1);
        }
    }else{
        if(address) {
            _sa_dst.sin_family = AF_INET;
            _sa_dst.sin_port = htons(address->port);
            memcpy(&_sa_dst.sin_addr, address->addr_ptr, address->addr_len);

            if (sendto(_socket_server, data, data_len, 0, (const struct sockaddr *)&_sa_dst, sizeof(sockaddr_in))==-1) {
                tr_debug("M2MConnectionHandlerPimpl::send_data - Error Code is %d\n",errno);
                _observer.socket_error(1);
            } else {
                 success = true;
                _observer.data_sent();
            }
        } else {
            //TODO: Define memory fail error code
            _observer.socket_error(3);
        }
    }
    return success;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    _receive_data = false;
}
