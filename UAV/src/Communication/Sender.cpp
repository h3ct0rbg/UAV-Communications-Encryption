#include "Sender.hpp"

#ifdef _WIN32
#define CLOSE_SOCKET(s) closesocket(s)
#else
#define CLOSE_SOCKET(s) close(s)
#endif

Sender::Sender(MessageQueue& queue, SOCKET sendSocket)
    : messageQueue(queue), sendSocket(sendSocket), running(false) {}

Sender::~Sender() {
    stop();
}

void Sender::start() {
    running = true;
    sendThread = std::thread(&Sender::sendMessages, this);
}

void Sender::stop() {
    running = false;
    if (sendThread.joinable()) {
        sendThread.join();
    }
}

void Sender::sendMessages() {
    const int maxPayloadSize = 65507 - 8; // Máximo tamaño de fragmento (menos encabezado)
    uint32_t messageId = 0;              // ID único para cada mensaje

    while (running) {
        // Extraer un mensaje de la cola
        std::vector<uint8_t> message = messageQueue.popMessage();
        
        // Dividir el mensaje en fragmentos
        size_t totalFragments = (message.size() + maxPayloadSize - 1) / maxPayloadSize;

        for (size_t i = 0; i < totalFragments; ++i) {
            size_t offset = i * maxPayloadSize;
            size_t fragmentSize = min(maxPayloadSize, message.size() - offset);

            // Crear el fragmento con encabezado
            std::vector<uint8_t> fragment(8 + fragmentSize);
            fragment[0] = (messageId >> 24) & 0xFF;
            fragment[1] = (messageId >> 16) & 0xFF;
            fragment[2] = (messageId >> 8) & 0xFF;
            fragment[3] = messageId & 0xFF;
            fragment[4] = (totalFragments >> 8) & 0xFF;
            fragment[5] = totalFragments & 0xFF;
            fragment[6] = (i >> 8) & 0xFF;
            fragment[7] = i & 0xFF;

            std::copy(message.begin() + offset, message.begin() + offset + fragmentSize, fragment.begin() + 8);

            // Enviar el fragmento
            int bytesSent = send(sendSocket,
                reinterpret_cast<const char*>(fragment.data()),
                fragment.size(), 0);

            if (bytesSent < 0) {
                std::cerr << "Error enviando el fragmento " << i << " del mensaje ID " << messageId << std::endl;
            }
        }

        // Incrementar el ID del mensaje
        messageId++;
    }

    // Cerrar el socket al finalizar
    CLOSE_SOCKET(sendSocket);
}