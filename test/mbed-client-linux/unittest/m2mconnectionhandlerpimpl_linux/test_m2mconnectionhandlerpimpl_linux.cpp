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
#include "CppUTest/TestHarness.h"
#include "test_m2mconnectionhandlerpimpl_linux.h"
#include "mbed-client-linux/m2mconnectionhandlerpimpl.h"
#include "m2mconnectionobserver.h"
#include "m2msecurity.h"
#include "common_stub.h"
#include "m2mconnectionsecurity_stub.h"

class M2MConnection_TestObserver : public M2MConnectionObserver {

public:
    M2MConnection_TestObserver():
    obj(NULL),
    dataAvailable(false),
    error(false),
    addressReady(false),
    dataSent(false)
    {}

    virtual ~M2MConnection_TestObserver(){}

    void set_class_object(M2MConnectionHandlerPimpl *impl) {obj = impl;}
    void data_available(uint8_t*,
                        uint16_t,
                        const M2MConnectionObserver::SocketAddress &){
        dataAvailable = true;
        if(obj) {
            obj->_receive_data = false;
        }
    }

    void socket_error(uint8_t error_code, bool retry = true){error = true;}

    void address_ready(const M2MConnectionObserver::SocketAddress &,
                       M2MConnectionObserver::ServerType,
                       const uint16_t){addressReady = true;}

    void data_sent(){dataSent = true;}

    bool dataAvailable;
    bool error;
    bool addressReady;
    bool dataSent;
    M2MConnectionHandlerPimpl *obj;
};

Test_M2MConnectionHandlerPimpl_linux::Test_M2MConnectionHandlerPimpl_linux()
{
    observer = new M2MConnection_TestObserver();
    m2mconnectionsecurityimpl_stub::clear();
    common_stub::int_value = 0;
    common_stub::thread = 14;
    handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::NOT_SET, M2MInterface::Uninitialized);

}

Test_M2MConnectionHandlerPimpl_linux::~Test_M2MConnectionHandlerPimpl_linux()
{
    handler->_listen_thread = 1;
    delete handler;
    delete observer;
}

void Test_M2MConnectionHandlerPimpl_linux::test_bind_connection()
{
    CHECK( handler->bind_connection(7) == true);
}

void Test_M2MConnectionHandlerPimpl_linux::test_resolve_server_address()
{
    M2MSecurity* sec = new M2MSecurity(M2MSecurity::M2MServer);
    common_stub::char_value = NULL;
    /* Stack uninitialized, socket_server will be -1, DnsResolvingFailed */
    common_stub::error = SOCKET_ERROR_NONE;
    M2MConnectionHandlerPimpl* tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::Uninitialized);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    delete tcp_handler;

    /* Socket bind() return -1, DnsResolvingFailed */
    observer->error = false;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::int_value = -1;
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    common_stub::int_value = 0;
    delete tcp_handler;
    tcp_handler = NULL;

    /* Socket bind() ipv6 return -1, DnsResolvingFailed */
    observer->error = false;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::int_value = -1;
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::LwIP_IPv6);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    common_stub::int_value = 0;
    delete tcp_handler;
    tcp_handler = NULL;

    /* Socket bind() stack uninitialized return -1, DnsResolvingFailed */
    observer->error = false;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::int_value = -1;
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::Uninitialized);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    common_stub::int_value = 0;
    delete tcp_handler;
    tcp_handler = NULL;

    /* Security implementation missing, SSL_CONNECTION_ERROR */
    observer->error = false;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;
    tcp_handler = NULL;

    /* _security_impl->init(security) return -1, SSL_CONNECTION_ERROR */
    observer->error = false;
    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    m2mconnectionsecurityimpl_stub::int_value = -1;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* _security_impl->connect(_base) return -1, SSL_CONNECTION_ERROR */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 0;
    m2mconnectionsecurityimpl_stub::connect_int_value = -1;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* TCP RESOLVED */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    m2mconnectionsecurityimpl_stub::connect_int_value = 0;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* TCP QUEUE RESOLVED */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::int2_value = 0;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::TCP_QUEUE, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;


    /* UDP ipv4 success */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* UDP ipv4 connect() return -1 */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::int2_value = -1;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    common_stub::addrinfo->ai_next = NULL;
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv4);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* UDP ipv6 success */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET6;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv6);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;


    /* UDP nanostack success */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET6;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::Nanostack_IPv6);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* UDP ipv6 success - close socket in resolve_hostname */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET6;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv6);
    tcp_handler->create_socket();
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == true);
    CHECK(observer->error == false);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* UDP ipv6 TODO */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::connect_int_value = -1;
    common_stub::int2_value = 0;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET6;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv6);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;

    /* UDP ipv6 connect() fail */
    conSec = new M2MConnectionSecurity(M2MConnectionSecurity::DTLS);
    observer->error = false;
    m2mconnectionsecurityimpl_stub::use_inc_int = false;
    common_stub::int2_value = -1;
    common_stub::error = SOCKET_ERROR_NONE;
    common_stub::addrinfo = (addrinfo*)malloc(sizeof(addrinfo));
    common_stub::addrinfo->ai_family = AF_INET6;
    common_stub::addrinfo->ai_addr = (sockaddr*)malloc(sizeof(sockaddr));
    common_stub::addrinfo->ai_next = NULL;
    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, conSec , M2MInterface::UDP, M2MInterface::LwIP_IPv6);
    CHECK(tcp_handler->resolve_server_address("10", 7, M2MConnectionObserver::LWM2MServer, sec) == false);
    CHECK(observer->error == true);
    free(common_stub::addrinfo->ai_addr);
    free(common_stub::addrinfo);
    common_stub::addrinfo = NULL;
    delete tcp_handler;
    delete sec;
}

void Test_M2MConnectionHandlerPimpl_linux::test_send_data()
{
    sn_nsdl_addr_s* addr = (sn_nsdl_addr_s*)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));
    uint8_t* data = (uint8_t*)malloc(5);
    CHECK( false == handler->send_data(data, 0 , NULL));

    handler->_stack = M2MInterface::LwIP_IPv4;
    common_stub::int_value = 4;
    CHECK(true == handler->send_data(data, 0 , addr));

    handler->_stack = M2MInterface::LwIP_IPv6;
    CHECK(true == handler->send_data(data, 0 , addr));

    /*handler->_stack = M2MInterface::Uninitialized;

    CHECK(true == handler->send_data(data, 0 , addr));

    handler->_stack = M2MInterface::LwIP_IPv6;*/

    M2MConnectionHandlerPimpl* tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::Uninitialized);
    common_stub::int_value = 4;
    CHECK(true == tcp_handler->send_data(data, 0 , addr));
    delete tcp_handler;

    common_stub::int_value = -1;
    CHECK(false == handler->send_data(data, 0 , addr));


    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    m2mconnectionsecurityimpl_stub::int_value = 0;
    CHECK(false == handler->send_data(data, 0 , addr));
    m2mconnectionsecurityimpl_stub::int_value = 5;
    CHECK(true == handler->send_data(data, 0 , addr));
    handler->_security_impl = NULL;
    delete conSec;

    free(data);
    free(addr);
}

void Test_M2MConnectionHandlerPimpl_linux::test_start_listening_for_data()
{
    handler->start_listening_for_data();
}

void Test_M2MConnectionHandlerPimpl_linux::test_data_receive()
{
    handler->data_receive(NULL);
    handler->_stack = M2MInterface::LwIP_IPv4;
    M2MConnectionHandlerPimpl *obj = new M2MConnectionHandlerPimpl(NULL,
                                                                   *observer,
                                                                   NULL,
                                                                   M2MInterface::TCP_QUEUE,
                                                                   M2MInterface::LwIP_IPv4);

    handler->_receive_data = true;
    observer->error = false;
    common_stub::int_value = -1;
    handler->data_receive(obj);
    CHECK(observer->error == true);
    CHECK(handler->_receive_data == false);

    M2MConnectionHandlerPimpl* tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::Uninitialized);
    tcp_handler->_receive_data = true;
    observer->error = false;
    common_stub::int_value = 2;
    tcp_handler->data_receive(obj);
    CHECK(observer->error == true);
    CHECK(tcp_handler->_receive_data == false);
    delete tcp_handler;

    tcp_handler = new M2MConnectionHandlerPimpl(NULL, *observer, NULL , M2MInterface::TCP, M2MInterface::LwIP_IPv4);
    tcp_handler->_receive_data = true;
    observer->error = false;
    observer->set_class_object(tcp_handler);
    common_stub::int_value = 6;
    tcp_handler->data_receive(obj);
    CHECK(observer->error == false);
    CHECK(tcp_handler->_receive_data == false);

    tcp_handler->_receive_data = true;
    observer->error = false;
    observer->set_class_object(tcp_handler);
    common_stub::int_value = 2;
    tcp_handler->data_receive(obj);
    CHECK(observer->error == true);
    CHECK(tcp_handler->_receive_data == false);

    delete tcp_handler;

    observer->set_class_object(handler);
    handler->_receive_data = true;    
    observer->dataAvailable = false;
    common_stub::int_value = 6;
    handler->data_receive(obj);
    CHECK(observer->dataAvailable == true);

    handler->_stack = M2MInterface::LwIP_IPv6;
    handler->_receive_data = true;
    observer->dataAvailable = false;
    handler->data_receive(obj);
    CHECK(observer->dataAvailable == true);

    handler->_stack = M2MInterface::Uninitialized;
    handler->_receive_data = true;
    observer->error = false;
    observer->dataAvailable = false;
    handler->data_receive(obj);
    CHECK(observer->error == true);
    CHECK(observer->dataAvailable == false);

    handler->_stack = M2MInterface::LwIP_IPv4;
    M2MConnectionSecurity* conSec = new M2MConnectionSecurity(M2MConnectionSecurity::TLS);
    handler->_security_impl = conSec;
    handler->_use_secure_connection = true;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::int_value = -1;
    observer->error = false;
    handler->data_receive(obj);
    CHECK(observer->error == true);
    CHECK(handler->_receive_data == false);

    observer->dataAvailable = false;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 0;
    handler->data_receive(obj);
    CHECK(handler->_receive_data == false);

    observer->dataAvailable = false;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 10;
    handler->data_receive(obj);
    CHECK(handler->_receive_data == false);
    CHECK(observer->dataAvailable == true);

    handler->_stack = M2MInterface::LwIP_IPv6;
    observer->dataAvailable = false;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 0;
    handler->data_receive(obj);
    CHECK(handler->_receive_data == false);
    CHECK(observer->dataAvailable == false);

    handler->_stack = M2MInterface::LwIP_IPv6;
    observer->dataAvailable = false;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 10;
    handler->data_receive(obj);
    CHECK(handler->_receive_data == false);
    CHECK(observer->dataAvailable == true);

    handler->_stack = M2MInterface::Uninitialized;
    observer->dataAvailable = false;
    handler->_receive_data = true;
    m2mconnectionsecurityimpl_stub::use_inc_int = true;
    m2mconnectionsecurityimpl_stub::inc_int_value = 0;
    handler->data_receive(obj);
    CHECK(handler->_receive_data == false);
    //CHECK(observer->dataAvailable == true);

    handler->_security_impl = NULL;
    delete conSec;

    delete obj;
    obj = NULL;
}

void Test_M2MConnectionHandlerPimpl_linux::test_stop_listening()
{
    handler->_receive_data == true;
    handler->stop_listening();
    CHECK(handler->_receive_data == false);
}

void Test_M2MConnectionHandlerPimpl_linux::test_send_to_socket()
{
    const char buf[] = "hello";
    handler->send_to_socket((unsigned char *)&buf, 5);

    handler->_stack = M2MInterface::LwIP_IPv4;
    handler->send_to_socket((unsigned char *)&buf, 5);

    handler->_stack = M2MInterface::LwIP_IPv6;
    handler->send_to_socket((unsigned char *)&buf, 5);
}

void Test_M2MConnectionHandlerPimpl_linux::test_receive_from_socket()
{
    unsigned char *buf = (unsigned char *)malloc(6);
    handler->receive_from_socket(buf, 5);
    handler->_stack = M2MInterface::LwIP_IPv4;
    handler->receive_from_socket(buf, 5);
    handler->_stack = M2MInterface::LwIP_IPv6;
    handler->receive_from_socket(buf, 5);
    free(buf);
}

void Test_M2MConnectionHandlerPimpl_linux::test_handle_connection_error()
{
    handler->handle_connection_error(4);
    CHECK(observer->error == true);
}
