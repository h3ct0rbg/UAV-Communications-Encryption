#ifndef MESSAGEQUEUE_HPP
#define MESSAGEQUEUE_HPP

#include <queue>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <cstdint>

class MessageQueue {
public:
    // Agrega un mensaje a la cola
    void pushMessage(const std::vector<uint8_t>& message);

    // Extrae el siguiente mensaje de la cola (bloquea si la cola est� vac�a)
    std::vector<uint8_t> popMessage();

private:
    std::queue<std::vector<uint8_t>> queue;         // Cola de mensajes cifrados
    std::mutex mtx;                                 // Mutex para sincronizaci�n de acceso a la cola
    std::condition_variable cv;                     // Variable de condici�n para notificaci�n
};

#endif // MESSAGEQUEUE_HPP