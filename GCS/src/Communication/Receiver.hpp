#ifndef RECEIVER_HPP
#define RECEIVER_HPP

#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <map>
#include "MessageQueue.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif

class Receiver {
public:
    Receiver(MessageQueue& messageQueue, SOCKET listenSocket);
    ~Receiver();

    void start();  // Inicia la recepción de mensajes
    void stop();   // Detiene la recepción de mensajes

private:
    void receiveMessages();     // Método que escucha los mensajes

    MessageQueue& messageQueue; // Cola para almacenar los mensajes recibidos
    SOCKET listenSocket;        // Descriptor del socket UDP
    std::thread receiveThread;  // Hilo para la recepción
    std::atomic<bool> running;  // Indica si el hilo está en ejecución
};

#endif // RECEIVER_HPP