#include "MessageQueue.hpp"

void MessageQueue::pushMessage(const std::vector<uint8_t>& message) {
    std::unique_lock<std::mutex> lock(mtx);
    queue.push(message);        // Colocar el mensaje en la cola
    cv.notify_one();            // Notificar a los consumidores en espera
}

std::vector<uint8_t> MessageQueue::popMessage() {
    std::unique_lock<std::mutex> lock(mtx);
    // Esperar hasta que haya mensajes disponibles
    cv.wait(lock, [this] { return !queue.empty(); });

    std::vector<uint8_t> message = queue.front(); // Obtener el mensaje más antiguo
    queue.pop();                                  // Remover el mensaje de la cola
    return message;
}