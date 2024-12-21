#ifndef CONNECT_HPP
#define CONNECT_HPP

#include <string>
#include <stdexcept>
#include <iostream>
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
    Connect(uint16_t port, const std::string& serverIP);
    ~Connect();

    bool initTCPConnection();      // Inicia la conexi�n TCP
    void closeTCPConnection();     // Cierra la conexi�n TCP
    bool initUDPConnection();      // Inicia la conexi�n UDP
    void closeUDPConnection();     // Cierra la conexi�n UDP
    bool exchangeCertificates();   // Intercambia y valida los CA
    void genKey();                 // Genera la clave de cifrado derivada usando ECDH

    std::vector<uint8_t> getDerivedKey();
    const int& getSendSock() const;

private:
    uint16_t port;           // Puerto del GCS
    std::string serverIP;    // Direcci�n IP del GCS
    int sendSockfd;          // Socket de comunicaci�n
    SSL_CTX* sslCtx;         // Contexto SSL
    SSL* ssl;                // Conexi�n SSL

    std::vector<uint8_t> derivedKey; // Clave de cifrado derivada
};

#endif // CONNECT_HPP