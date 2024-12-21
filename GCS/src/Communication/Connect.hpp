#ifndef CONNECT_HPP
#define CONNECT_HPP

#include <string>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif

class Connect {
public:
    Connect(uint16_t port);
    ~Connect();

    bool initTCPConnection();      // Inicia la conexión TCP
    void closeTCPConnection();     // Cierra la conexión TCP
    bool initUDPConnection();      // Inicia la conexión UDP
    void closeUDPConnection();     // Cierra la conexión UDP
    bool exchangeCertificates();   // Intercambia y valida los CA
    void genKey();                 // Genera la clave de cifrado derivada usando ECDH

    std::vector<uint8_t> getDerivedKey();
    const int& getListenSock() const;
    const int& getClientSock() const;

private:
    uint16_t port;      // Puerto escucha
    int listenSockfd;   // Socket GCS
    int clientSockfd;   // Socket UAV

    SSL_CTX* sslCtx;    // Contexto SSL
    SSL* ssl;           // Conexión SSL

    std::vector<uint8_t> derivedKey; // Clave de cifrado
};

#endif // CONNECT_HPP