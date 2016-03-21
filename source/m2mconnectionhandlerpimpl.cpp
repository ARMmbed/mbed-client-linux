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
#include "mbed-client/m2msecurity.h"


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

    if(_listen_thread > 0) {
        if (!pthread_equal(_listen_thread, pthread_self())) {
            pthread_detach(_listen_thread);
        }
    }

    if(_socket_server > 0) {        
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
    struct addrinfo *addr_info = NULL;
    int r;
    struct sockaddr_in *a = NULL;
    struct sockaddr_in6 *a6 = NULL;
    /* Resolve hostname of NSP */
    r = getaddrinfo(address, NULL, NULL, &addr_info);
    if (r == 0 && addr_info) {
        /* Take the first address and give it to NSDL and EDTLS*/
        switch(addr_info->ai_family) {
        case AF_INET:
            //tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - address is IPv4\n");
            char ip_address[INET_ADDRSTRLEN];            
            a = (struct sockaddr_in*)addr_info->ai_addr;
            if(a) {
                inet_ntop(AF_INET,&(a->sin_addr),ip_address,INET_ADDRSTRLEN);
                if(_socket_server == -1) {
                    if(_binding_mode == M2MInterface::TCP ||
                       _binding_mode == M2MInterface::TCP_QUEUE ){
                        _socket_server=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    }else{
                        _socket_server=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    }
                    bind_ipv4_socket();
                }

                inet_pton(AF_INET, ip_address, &_resolved_address);

                if(_received_packet_address) {
                    success = true;
                    _received_packet_address->_port = server_port;
                    memcpy(_received_packet_address->_address, _resolved_address, 4);
                    _received_packet_address->_stack = M2MInterface::LwIP_IPv4;
                    _stack = M2MInterface::LwIP_IPv4;
                    _received_packet_address->_length = 4;
                }
                _sa_dst.sin_family = AF_INET;
                _sa_dst.sin_port = ntohs(server_port);
                memcpy(&_sa_dst.sin_addr, _received_packet_address->_address, _received_packet_address->_length);
                connect(_socket_server, (const struct sockaddr *)&_sa_dst, _slen_sa_dst);
            }
            break;
        case AF_INET6:
           // tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - address is IPv6\n");
            char ip6_address[INET6_ADDRSTRLEN];            
            a6 =  (struct sockaddr_in6*)addr_info->ai_addr;
            if(a6) {
                inet_ntop(AF_INET6,
                          &(a6->sin6_addr),
                          ip6_address,
                          INET6_ADDRSTRLEN);

                if(_socket_server == -1) {
                    if(_binding_mode == M2MInterface::TCP ||
                       _binding_mode == M2MInterface::TCP_QUEUE ){
                        _socket_server=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
                    }else{
                        _socket_server=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                    }
                    bind_ipv6_socket();
                }

                inet_pton(AF_INET6, ip6_address, &_resolved_address);
                if(_received_packet_address) {
                    success = true;
                    _received_packet_address->_port = server_port;
                    memcpy(_received_packet_address->_address,
                           _resolved_address,
                           sizeof(_resolved_address));
                    _received_packet_address->_stack = M2MInterface::LwIP_IPv6;
                    _stack = M2MInterface::LwIP_IPv6;
                    _received_packet_address->_length = sizeof(_resolved_address);
                }
                _sa_dst6.sin6_family = AF_INET6;
                _sa_dst6.sin6_port = ntohs(server_port);
                memcpy(&_sa_dst6.sin6_addr,
                       _received_packet_address->_address,
                       _received_packet_address->_length);
                connect(_socket_server, (const struct sockaddr *)&_sa_dst6, _slen_sa_dst6);
            }
            break;
        }

        freeaddrinfo(addr_info);

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
            _observer.address_ready(*_received_packet_address,server_type, server_port);
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

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    if (_stack == M2MInterface::LwIP_IPv4) {
        return sendto(_socket_server, (char*)buf, len, 0, (const struct sockaddr *)&_sa_dst, _slen_sa_dst);
    }
    else if(_stack == M2MInterface::LwIP_IPv6) {
        return sendto(_socket_server, (char*)buf, len, 0, (const struct sockaddr *)&_sa_dst6, _slen_sa_dst6);
    }
    else {
        return -1;
    }
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len)
{
    if (_stack == M2MInterface::LwIP_IPv4) {
        return recvfrom(_socket_server, buf,
                          len, 0, (struct sockaddr *)&_sa_dst,
                          (socklen_t*)&_slen_sa_dst);
    }
    else if(_stack == M2MInterface::LwIP_IPv6) {
        return recvfrom(_socket_server, buf,
                          len, 0, (struct sockaddr *)&_sa_dst6,
                          (socklen_t*)&_slen_sa_dst6);
    }
    else {
        return -1;
    }
}

void M2MConnectionHandlerPimpl::data_receive(void *object)
{
    if(object != NULL){
        M2MConnectionHandlerPimpl *thread_object = (M2MConnectionHandlerPimpl*) object;
        if(thread_object) {
            pthread_join(_listen_thread, NULL);
        }
        int16_t rcv_size = -1;
        memset(_received_buffer, 0, BUFFER_LENGTH);

        if( _use_secure_connection ){
            while(_receive_data){
                int rcv_size = _security_impl->read(_received_buffer, BUFFER_LENGTH);
                if(rcv_size > 0){
                    if (_stack == M2MInterface::LwIP_IPv4) {
                        _received_packet_address->_port = ntohs(_sa_dst.sin_port);
                    }
                    else if (_stack == M2MInterface::LwIP_IPv6) {
                        _received_packet_address->_port = ntohs(_sa_dst6.sin6_port);
                    }                    
                    _observer.data_available(_received_buffer, rcv_size, *_received_packet_address);
                }
                else if(rcv_size == 0){
                    //We are in initializing phase, so do nothing
                }
                else{
                    _receive_data = false;
                    _observer.socket_error(1);
                }
                memset(_received_buffer, 0, BUFFER_LENGTH);
            }
        }else{
            while(_receive_data) {
                char rcv_in_addr[256];
                memset(rcv_in_addr,0,256);
                switch (_stack) {
                case M2MInterface::LwIP_IPv4:
                    rcv_size=recvfrom(_socket_server, _received_buffer,
                                  BUFFER_LENGTH, 0, (struct sockaddr *)&_sa_dst,
                                  (socklen_t*)&_slen_sa_dst);
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
                    rcv_size=recvfrom(_socket_server, _received_buffer,
                                  BUFFER_LENGTH, 0, (struct sockaddr *)&_sa_dst6,
                                  (socklen_t*)&_slen_sa_dst6);
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

                if (rcv_size == -1) {
                   //TODO: Define receive error code
                    _observer.socket_error(2);
                    _receive_data = false;
                }

                /* If message received.. */
                if(rcv_size > 0 && _received_packet_address) {
                    if(_binding_mode == M2MInterface::TCP ||
                       _binding_mode == M2MInterface::TCP_QUEUE){
                        //We need to "shim" out the length from the front
                        if( rcv_size > 4 ){
                            uint64_t len = (_received_buffer[0] << 24 & 0xFF000000) + (_received_buffer[1] << 16 & 0xFF0000);
                            len += (_received_buffer[2] << 8 & 0xFF00) + (_received_buffer[3] & 0xFF);
                            uint8_t* buf = (uint8_t*)malloc(len);
                            memmove(buf, _received_buffer+4, len);
                            _observer.data_available(buf, len, *_received_packet_address);
                            free(buf);
                        }else{
                            _observer.socket_error(2);
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

void M2MConnectionHandlerPimpl::bind_ipv4_socket()
{
    memset((char *) &_sa_src, 0, sizeof(_sa_src));
    _sa_src.sin_family = AF_INET;
    _sa_src.sin_port = htons(_listen_port);

    /* Listen to the port */
    _sa_src.sin_addr.s_addr = INADDR_ANY;
    bind(_socket_server, (struct sockaddr *) &_sa_src, sizeof(_sa_src));

}

void M2MConnectionHandlerPimpl::bind_ipv6_socket()
{
    memset((char *) &_sa_src6, 0, sizeof(_sa_src6));
    _sa_src6.sin6_family = AF_INET6;
    _sa_src6.sin6_port = htons(_listen_port);

    /* Listen to the port */
    _sa_src6.sin6_addr = in6addr_any;
    bind(_socket_server, (struct sockaddr *) &_sa_src6, sizeof(_sa_src6));
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    bool success = false;
    if(data){
        if( _use_secure_connection ){
            if( _security_impl->send_message(data, data_len) > 0){
                success = true;
                _observer.data_sent();
            }else{
                _observer.socket_error(1);
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
                if(_binding_mode == M2MInterface::TCP ||
                   _binding_mode == M2MInterface::TCP_QUEUE){
                    //We need to "shim" the length in front
                    uint16_t d_len = data_len+4;
                    uint8_t* d = (uint8_t*)malloc(data_len+4);

                    d[0] = (data_len >> 24 )& 0xff;
                    d[1] = (data_len >> 16 )& 0xff;
                    d[2] = (data_len >> 8 )& 0xff;
                    d[3] = data_len & 0xff;
                    memmove(d+4, data, data_len);
                    ret = sendto(_socket_server, d, d_len, 0, (const struct sockaddr *)&_sa_dst, sizeof(sockaddr_in));
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

                if (ret==-1) {
                    //tr_debug("M2MConnectionHandlerPimpl::send_data - Error Code is %d\n",errno);
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
    }
    return success;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    _receive_data = false;
}

void M2MConnectionHandlerPimpl::handle_connection_error(int /*error*/)
{
    //This will come from M2MConnectionSecurity class
    _observer.socket_error(4);
}
