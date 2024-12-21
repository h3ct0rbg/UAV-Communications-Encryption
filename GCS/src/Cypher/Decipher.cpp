#include "Decipher.hpp"
#include <openssl/evp.h>
#include <iostream>
#include <stdexcept>
#include <iomanip>

Decipher::Decipher(const std::vector<uint8_t>& derivedKey, MessageQueue& messageQueue, FrameQueue& frameQueue)
    : derivedKey(derivedKey), messageQueue(messageQueue), frameQueue(frameQueue), running(false), ctx(EVP_CIPHER_CTX_new()) {}

Decipher::~Decipher() {
    stop();
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);  // Liberar el contexto de cifrado
    }
}

void Decipher::start() {
    running = true;
    decipherThread = std::thread(&Decipher::decipherMessages, this);
}

void Decipher::stop() {
    running = false;
    if (decipherThread.joinable()) {
        decipherThread.join();
    }
}

void Decipher::decipherMessages() {
    while (running) {
        try {
            // Usamos popMessage() para obtener el siguiente mensaje cifrado
            std::vector<uint8_t> encryptedMessage = messageQueue.popMessage();

            // Descifrar el mensaje
            std::vector<uint8_t> decryptedMessage = decrypt(encryptedMessage);

            // Colocar el mensaje descifrado en FrameQueue
            frameQueue.pushFrame(decryptedMessage);

        }
        catch (const std::exception& e) {
            std::cerr << "Error en el descifrado: " << e.what() << std::endl;
        }
    }
}

std::vector<uint8_t> Decipher::decrypt(const std::vector<uint8_t>& encryptedMessage) {
    const int IV_SIZE = 12;    // Tamaño del IV para AES-GCM
    const int TAG_SIZE = 16;   // Tamaño del Tag para AES-GCM

    // Comprobamos que el mensaje tiene al menos IV + Tag + Datos Cifrados
    if (encryptedMessage.size() < IV_SIZE + TAG_SIZE) {
        throw std::runtime_error("El mensaje cifrado es demasiado pequeño.");
    }

    // Extraemos el IV y el Tag del mensaje cifrado
    std::vector<uint8_t> iv(encryptedMessage.begin(), encryptedMessage.begin() + IV_SIZE);
    std::vector<uint8_t> tag(encryptedMessage.begin() + IV_SIZE, encryptedMessage.begin() + IV_SIZE + TAG_SIZE);
    std::vector<uint8_t> cipherText(encryptedMessage.begin() + IV_SIZE + TAG_SIZE, encryptedMessage.end());

    std::vector<uint8_t> decryptedData(cipherText.size());  // Buffer para los datos descifrados

    int totalLen = 0;  // Tamaño total acumulado

    try {
        // Inicialización del descifrado
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, derivedKey.data(), iv.data()) != 1) {
            throw std::runtime_error("Error inicializando el descifrado.");
        }

        // Comprobamos el Tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
            throw std::runtime_error("Error al establecer el Tag.");
        }

        int len;
        // Desciframos los datos (EVP_DecryptUpdate)
        if (EVP_DecryptUpdate(ctx, decryptedData.data(), &len, cipherText.data(), cipherText.size()) != 1) {
            throw std::runtime_error("Error en el descifrado de datos.");
        }
        totalLen += len;  // Acumular la longitud de los datos descifrados

        // Finalizamos el descifrado (EVP_DecryptFinal_ex)
        if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + totalLen, &len) != 1) {
            throw std::runtime_error("Error finalizando el descifrado.");
        }
        totalLen += len;  // Acumular la longitud final de los datos descifrados

        // Ajustamos el tamaño final del vector
        decryptedData.resize(totalLen);
    }
    catch (const std::exception& e) {
        std::cerr << "Error en el descifrado: " << e.what() << std::endl;
        throw;  // Lanza la excepción para que se maneje en el nivel superior
    }

    return decryptedData;
}