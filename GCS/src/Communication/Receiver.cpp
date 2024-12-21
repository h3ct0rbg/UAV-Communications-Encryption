#include "Receiver.hpp"

#ifdef _WIN32
#define CLOSE_SOCKET(s) closesocket(s)
#else
#define CLOSE_SOCKET(s) close(s)
#endif

Receiver::Receiver(MessageQueue& queue, SOCKET listenSocket)
    : messageQueue(queue), listenSocket(listenSocket), running(false) {}

Receiver::~Receiver() {
    stop();
}

void Receiver::start() {
    running = true;
    receiveThread = std::thread(&Receiver::receiveMessages, this);
}

void Receiver::stop() {
    running = false;
    if (receiveThread.joinable()) {
        receiveThread.join();
    }
}

void Receiver::receiveMessages() {
    const int bufferSize = 65507;
    std::vector<uint8_t> buffer(bufferSize);
    sockaddr_in senderAddr = {};
    socklen_t senderAddrLen = sizeof(senderAddr);

    // Mapa para almacenar fragmentos por mensaje ID
    std::map<uint32_t, std::vector<std::vector<uint8_t>>> fragmentsMap;
    std::map<uint32_t, size_t> totalFragmentsMap;

    while (running) {
        // Recibir datos a través del socket UDP
        int bytesReceived = recvfrom(listenSocket,
            reinterpret_cast<char*>(buffer.data()),
            bufferSize, 0,
            reinterpret_cast<struct sockaddr*>(&senderAddr),
            &senderAddrLen);

        if (bytesReceived < 0) {
            std::cerr << "Error recibiendo el mensaje." << std::endl;
            continue;
        }

        // Leer el encabezado del fragmento
        uint32_t messageId = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
        size_t totalFragments = (buffer[4] << 8) | buffer[5];
        size_t fragmentIndex = (buffer[6] << 8) | buffer[7];

        // Almacenar el fragmento
        fragmentsMap[messageId].resize(totalFragments);
        fragmentsMap[messageId][fragmentIndex] = std::vector<uint8_t>(buffer.begin() + 8, buffer.begin() + bytesReceived);
        totalFragmentsMap[messageId] = totalFragments;

        // Verificar si todos los fragmentos han llegado
        if (fragmentsMap[messageId].size() == totalFragments &&
            std::all_of(fragmentsMap[messageId].begin(), fragmentsMap[messageId].end(), [](const std::vector<uint8_t>& f) { return !f.empty(); })) {

            // Reconstruir el mensaje
            std::vector<uint8_t> completeMessage;
            for (const auto& fragment : fragmentsMap[messageId]) {
                completeMessage.insert(completeMessage.end(), fragment.begin(), fragment.end());
            }

            // Guardar el mensaje en la cola
            messageQueue.pushMessage(completeMessage);

            // Limpiar los fragmentos del mensaje procesado
            fragmentsMap.erase(messageId);
            totalFragmentsMap.erase(messageId);
        }
    }

    // Cerrar el socket al finalizar
    CLOSE_SOCKET(listenSocket);
}