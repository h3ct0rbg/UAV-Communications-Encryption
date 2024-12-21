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

    void start();  // Inicia el envío de mensajes
    void stop();   // Detiene el envío de mensajes

private:
    void sendMessages();         // Método que envía los mensajes

    MessageQueue& messageQueue;  // Cola de mensajes a enviar
    SOCKET sendSocket;           // Descriptor del socket UDP
    std::thread sendThread;      // Hilo para el envío
    std::atomic<bool> running;   // Indica si el hilo está en ejecución
};

#endif // SENDER_HPP