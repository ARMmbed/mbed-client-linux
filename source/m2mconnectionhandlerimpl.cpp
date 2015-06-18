/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include <sys/types.h>
#include <netdb.h>
#include "lwm2m-client-linux/m2mconnectionhandlerimpl.h"
#include "include/connthreadhelper.h"
#include "lwm2m-client/m2mconstants.h"
#include "libService/ns_trace.h"

M2MConnectionHandlerImpl::M2MConnectionHandlerImpl(M2MConnectionObserver &observer,
                                           M2MInterface::NetworkStack stack)
:_observer(observer),
 _stack(M2MInterface::Uninitialized),
 _socket_server(-1),
 _slen_sa_dst(sizeof(_sa_dst)),
 _listen_thread(0),
 _receive_data(false)
{
    __connection_impl = this;
    _received_packet_address = (M2MConnectionObserver::SocketAddress *)malloc(sizeof(M2MConnectionObserver::SocketAddress));
    if(_received_packet_address) {
        memset(_received_packet_address, 0, sizeof(M2MConnectionObserver::SocketAddress));
        _received_packet_address->_address = _received_address;
    }
}

M2MConnectionHandlerImpl::~M2MConnectionHandlerImpl()
{
    if(_received_packet_address) {
        free(_received_packet_address);
        _received_packet_address = NULL;
    }

    if(_listen_thread > 0) {
        if (!pthread_equal(_listen_thread, pthread_self())) {
            pthread_join(_listen_thread,NULL);
            pthread_cancel(_listen_thread);
        }
    }
    if(_socket_server > 0) {
        shutdown(_socket_server,SHUT_RDWR);
    }
    __connection_impl = NULL;
}

bool M2MConnectionHandlerImpl::bind_connection(const uint16_t listen_port)
{
    memset((char *) &_sa_src, 0, sizeof(_sa_src));
    _sa_src.sin_family = AF_INET;
    _sa_src.sin_port = htons(listen_port);

    /* Listen to the port */
    _sa_src.sin_addr.s_addr = INADDR_ANY;
    int ret = bind(_socket_server, (struct sockaddr *) &_sa_src, sizeof(_sa_src));
    return (ret == -1) ? false : true;
}

bool M2MConnectionHandlerImpl::resolve_server_address(const String& server_address,
                                                  const uint16_t server_port,
                                                  M2MConnectionObserver::ServerType server_type)
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
            tr_debug("M2MConnectionHandlerImpl::resolve_server_address - address is IPv4\n");
            char ip_address[INET_ADDRSTRLEN];
            a = (struct sockaddr_in*)addr->ai_addr;
            if(a) {
                inet_ntop(AF_INET,&(a->sin_addr),ip_address,INET_ADDRSTRLEN);

                if(_socket_server == -1) {
                   _socket_server=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
            tr_debug("M2MConnectionHandlerImpl::resolve_server_address - address is IPv6\n");
            char ip6_address[INET6_ADDRSTRLEN];
            a6 =  (struct sockaddr_in6*)addr->ai_addr;
            if(a6) {
                inet_ntop(AF_INET6,&(a6->sin6_addr),ip6_address,INET6_ADDRSTRLEN);
                if(_socket_server == -1) {
                   _socket_server=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
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

bool M2MConnectionHandlerImpl::listen_for_data()
{
    bool success = true;
    if(!_receive_data) {
        _receive_data = true;
        pthread_create(&_listen_thread, NULL,__listen_data_function, this);
    }
    return success;
}

void M2MConnectionHandlerImpl::data_receive(void *object)
{
    if(object != NULL){
        M2MConnectionHandlerImpl *thread_object = (M2MConnectionHandlerImpl*) object;
        if(thread_object) {
            pthread_detach(thread_object->_listen_thread);
        }
        int16_t rcv_size=0;
        memset(_received_buffer, 0, 1024);

        while(_receive_data) {
            char rcv_in_addr[256];
            memset(rcv_in_addr,0,32);
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
        }
    }
}

bool M2MConnectionHandlerImpl::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    bool success = false;
    if(address) {
        _sa_dst.sin_family = AF_INET;
        _sa_dst.sin_port = htons(address->port);
        memcpy(&_sa_dst.sin_addr, address->addr_ptr, address->addr_len);

        if (sendto(_socket_server, data, data_len, 0, (const struct sockaddr *)&_sa_dst, _slen_sa_dst)==-1) {
            //TODO: Define send error code
            _observer.socket_error(1);
        } else {
             success = true;
            _observer.data_sent();
        }
    } else {
        //TODO: Define memory fail error code
        _observer.socket_error(3);
    }
    return success;
}

void M2MConnectionHandlerImpl::close_connection()
{
    _receive_data = false;
}
