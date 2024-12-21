#ifndef DECIPHER_HPP
#define DECIPHER_HPP

#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include "../Communication/MessageQueue.hpp"
#include "FrameQueue.hpp"
#include <openssl/evp.h>

class Decipher {
public:
    Decipher(const std::vector<uint8_t>& derivedKey, MessageQueue& messageQueue, FrameQueue& frameQueue);
    ~Decipher();

    void start();   // Inicia el descifrado de mensajes
    void stop();    // Detiene el proceso de descifrado

private:
    void decipherMessages();  // Método que procesa y descifra los mensajes
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encryptedMessage);  // Función para descifrar los mensajes

    std::vector<uint8_t> derivedKey;  // Clave derivada para el descifrado
    MessageQueue& messageQueue; // Cola de mensajes cifrados
    FrameQueue& frameQueue;     // Cola para almacenar los mensajes descifrados
    std::thread decipherThread;
    std::atomic<bool> running;

    EVP_CIPHER_CTX* ctx;
};

#endif // DECIPHER_HPP