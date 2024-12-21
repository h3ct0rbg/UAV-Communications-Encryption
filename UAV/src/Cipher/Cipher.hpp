#ifndef Cipher_HPP
#define Cipher_HPP

#include "FrameQueue.hpp"
#include "../Communication/MessageQueue.hpp"
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <thread>
#include <atomic>

class Cipher {
public:
    Cipher(FrameQueue& frameQueue, MessageQueue& messageQueue, const std::vector<uint8_t>& encryptionKey);
    ~Cipher();

    void start(); // Inicia el cifrado de tramas
    void stop();  // Detiene el cifrado de tramas

private:
    void encryptFrames(); // Extrae y cifra las tramas

    FrameQueue& frameQueue;
    MessageQueue& messageQueue;
    std::vector<uint8_t> key;
    std::thread encryptionThread;
    std::atomic<bool> running;
};

#endif // Cipher_HPP