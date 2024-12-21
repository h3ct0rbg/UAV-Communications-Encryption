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

    void start();  // Inicia la recepci�n de mensajes
    void stop();   // Detiene la recepci�n de mensajes

private:
    void receiveMessages();     // M�todo que escucha los mensajes

    MessageQueue& messageQueue; // Cola para almacenar los mensajes recibidos
    SOCKET listenSocket;        // Descriptor del socket UDP
    std::thread receiveThread;  // Hilo para la recepci�n
    std::atomic<bool> running;  // Indica si el hilo est� en ejecuci�n
};

#endif // RECEIVER_HPP