#ifndef SENDER_HPP
#define SENDER_HPP

#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <cstdint>
#include "MessageQueue.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif

class Sender {
public:
    Sender(MessageQueue& messageQueue, SOCKET sendSocket);
    ~Sender();

    void start();  // Inicia el env�o de mensajes
    void stop();   // Detiene el env�o de mensajes

private:
    void sendMessages();         // M�todo que env�a los mensajes

    MessageQueue& messageQueue;  // Cola de mensajes a enviar
    SOCKET sendSocket;           // Descriptor del socket UDP
    std::thread sendThread;      // Hilo para el env�o
    std::atomic<bool> running;   // Indica si el hilo est� en ejecuci�n
};

#endif // SENDER_HPP