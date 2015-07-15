/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#ifndef M2M_CONNECTION_HANDLER_PIMPL_H__
#define M2M_CONNECTION_HANDLER_PIMPL_H__

#include "lwm2m-client/m2mconfig.h"
#include "lwm2m-client/m2minterface.h"
#include "lwm2m-client/m2mconnectionobserver.h"
#include "lwm2m-client/m2mconnectionsecurity.h"
#include "sn_nsdl.h"

#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h> /* For SIGIGN and SIGINT */
#include <unistd.h>
#include <errno.h>

class M2MConnectionHandler;

class M2MConnectionHandlerPimpl {
public:

    /**
    * @brief Constructor
    */
    M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                         M2MConnectionSecurity* sec,
                         M2MInterface::NetworkStack stack);

    /**
    * @brief Destructor
    */
    ~M2MConnectionHandlerPimpl();

    /**
    * @brief This binds the socket connection.
    * @param listen_port Port to listen for incoming connection.
    * @return true if successfulelse false.
    */
    bool bind_connection(const uint16_t listen_port);

    /**
    * @brief This resolves the server address. Output is
    * returned through callback
    * @param String server address.
    * @param uint16_t Server port.
    * @param ServerType, Server Type to be resolved.
    * @return true if address is valid else false.
    */
    bool resolve_server_address(const String& server_address,
                                const uint16_t server_port,
                                M2MConnectionObserver::ServerType server_type,
                                const M2MSecurity* security);

    /**
    * @brief Sends data, to the connected sent to server.
    * @param data, Data to be sent.
    */
    bool send_data(uint8_t *data_ptr,
                   uint16_t data_len,
                   sn_nsdl_addr_s *address_ptr);

    /**
    * @brief Listens for incoming data from remote server
    * @return true if successful else false.
    */
    bool start_listening_for_data();

    /**
    * @brief Stops listening for incoming data
    */
    void stop_listening();

    /**
     * @brief sendToSocket Sends directly to socket. This is used by
     * security classes to send after data has been encrypted.
     * @param buf Buffer to send
     * @param len Length of a buffer
     * @return Number of bytes sent or -1 if failed
     */
    int sendToSocket(const unsigned char *buf, size_t len);

    /**
     * @brief receiveFromSocket Receives directly from a socket. This
     * is used by security classes to receive raw data to be decrypted.
     * @param buf Buffer to send
     * @param len Length of a buffer
     * @return Number of bytes read or -1 if failed.
     */
    int receiveFromSocket(unsigned char *buf, size_t len);

public:
    void data_receive(void *object);


private:
    M2MConnectionHandler                    *_base;
    M2MConnectionObserver                   &_observer;
    M2MConnectionSecurity                   *_security_impl; //owned
    bool                                    _use_secure_connection;
    String                                  _server_address;
    char                                    _receive_buffer[1024];
    uint8_t                                 _resolved_address[16];
    M2MInterface::NetworkStack              _stack;
    uint8_t                                 _received_address[16];
    M2MConnectionObserver::SocketAddress    *_received_packet_address;
    int                                     _socket_server;
    struct sockaddr_in                      _sa_dst;
    struct sockaddr_in                      _sa_src;
    int                                     _slen_sa_dst;
    uint8_t                                 _received_buffer[1024];
    pthread_t                               _listen_thread; /* Thread for Listen data function */
    volatile bool                           _receive_data;

friend class Test_M2MConnectionHandlerPimpl;
friend class Test_M2MConnectionHandlerPimpl_linux;
friend class M2MConnection_TestObserver;
};
#endif //M2M_CONNECTION_HANDLER_PIMPL_H__

