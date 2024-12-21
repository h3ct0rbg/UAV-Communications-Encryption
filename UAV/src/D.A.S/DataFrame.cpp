#include "DataFrame.hpp"

DataFrame::DataFrame(DataAcquisition& acquisition, uint8_t sensorId, FrameQueue& frameQueue)
    : dataAcquisition(acquisition), sensorId(sensorId), frameQueue(frameQueue), running(false) {}

void DataFrame::start() {
    running = true;
    consumerThread = std::thread(&DataFrame::createFrame, this);
}

void DataFrame::stop() {
    running = false;
    if (consumerThread.joinable()) {
        consumerThread.join();
    }
}

void DataFrame::createFrame() {
    const uint16_t frameStart = 0xABCD;  // Inicio de Trama
    const uint8_t sensorStatus = 0x01;   // Estado del Sensor (Operativo)
    uint16_t sequenceNumber = 0;         // Número de secuencia

    while (running) {
        cv::Mat data = dataAcquisition.retrieveData(sensorId); // Extrae el último frame de la cola

        if (!data.empty()) {
            // Obtener el timestamp en milisegundos, limitado a 2 bytes (65,535 ms máx.)
            uint16_t timestamp = static_cast<uint16_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count() & 0xFFFF
                );

            // Convertir la imagen en un array de bytes
            std::vector<uchar> buffer;
            cv::imencode(".jpg", data, buffer);
            uint16_t dataLength = (buffer.size() > UINT16_MAX) ? UINT16_MAX : static_cast<uint16_t>(buffer.size()); // Longitud de los Datos del Sensor

            // Crear la trama de datos
            std::vector<uint8_t> frame;

            // Inicio de Trama (2 bytes)
            frame.push_back(static_cast<uint8_t>(frameStart >> 8));
            frame.push_back(static_cast<uint8_t>(frameStart & 0xFF));

            // Número de Secuencia (2 bytes)
            frame.push_back(static_cast<uint8_t>(sequenceNumber >> 8));
            frame.push_back(static_cast<uint8_t>(sequenceNumber & 0xFF));
            // Incrementar el número de secuencia y manejar el envolvimiento
            sequenceNumber = (sequenceNumber + 1) % 0x10000;  // Vuelve a 0 después de 0xFFFF

            // Timestamp (2 bytes en milisegundos)
            frame.push_back(static_cast<uint8_t>(timestamp >> 8));
            frame.push_back(static_cast<uint8_t>(timestamp & 0xFF));

            // Identificación del Sensor (1 byte)
            frame.push_back(sensorId);

            // Estado del Sensor (1 byte)
            frame.push_back(sensorStatus);

            // Longitud de los Datos del Sensor (2 bytes)
            frame.push_back(static_cast<uint8_t>(dataLength >> 8));
            frame.push_back(static_cast<uint8_t>(dataLength & 0xFF));

            // Datos del Sensor (Variable)
            frame.insert(frame.end(), buffer.begin(), buffer.end());

            // Agrega la trama a la cola para que Cipher la consuma
            frameQueue.pushFrame(frame);
        }
    }
}