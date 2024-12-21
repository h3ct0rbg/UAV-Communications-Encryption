#include "Cipher.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <stdexcept>

Cipher::Cipher(FrameQueue& frameQueue, MessageQueue& messageQueue, const std::vector<uint8_t>& encryptionKey)
    : frameQueue(frameQueue), messageQueue(messageQueue), key(encryptionKey), running(false) {}

Cipher::~Cipher() {
    stop();
}

void Cipher::start() {
    running = true;
    encryptionThread = std::thread(&Cipher::encryptFrames, this);
}

void Cipher::stop() {
    running = false;
    if (encryptionThread.joinable()) {
        encryptionThread.join();
    }
}

void Cipher::encryptFrames() {
    const int IV_SIZE = 12;      // Tamaño del IV para AES-GCM
    const int TAG_SIZE = 16;     // Tamaño del Tag para AES-GCM
    while (running) {
        std::vector<uint8_t> frame = frameQueue.popFrame();

        // Generar IV aleatorio para este mensaje
        std::vector<uint8_t> iv(IV_SIZE);
        if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
            std::cerr << "Error generando IV" << std::endl;
            continue;
        }

        // Preparar buffer de salida para datos cifrados y tag
        std::vector<uint8_t> encryptedData(frame.size());
        std::vector<uint8_t> tag(TAG_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error creando contexto de cifrado" << std::endl;
            continue;
        }

        try {
            // Inicializar cifrado AES-GCM con la clave y el IV
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
                EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                throw std::runtime_error("Error inicializando cifrado");
            }

            int len;
            // Cifrar el frame
            if (EVP_EncryptUpdate(ctx, encryptedData.data(), &len, frame.data(), frame.size()) != 1) {
                throw std::runtime_error("Error en cifrado de datos");
            }

            // Finalizar cifrado y obtener el tag
            if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + len, &len) != 1 ||
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
                throw std::runtime_error("Error finalizando cifrado");
            }

            // Crear la trama cifrada completa: IV + Tag + Datos Cifrados
            std::vector<uint8_t> encryptedFrame;
            encryptedFrame.insert(encryptedFrame.end(), iv.begin(), iv.end());              // Añadir IV
            encryptedFrame.insert(encryptedFrame.end(), tag.begin(), tag.end());            // Añadir Tag
            encryptedFrame.insert(encryptedFrame.end(), encryptedData.begin(), encryptedData.end());  // Añadir Datos Cifrados

            // Colocar la trama cifrada en MessageQueue
            messageQueue.pushMessage(encryptedFrame);
        }
        catch (const std::exception& e) {
            std::cerr << "Error durante el cifrado: " << e.what() << std::endl;
        }

        EVP_CIPHER_CTX_free(ctx);
    }
}