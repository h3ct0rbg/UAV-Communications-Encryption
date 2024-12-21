#include "DataFrame.hpp"

DataFrame::DataFrame(DataAcquisition& acquisition, FrameQueue& frameQueue)
    : dataAcquisition(acquisition), frameQueue(frameQueue), running(false) {}

DataFrame::~DataFrame() {
    stop();
}

void DataFrame::start() {
    running = true;
    consumerThread = std::thread(&DataFrame::processFrames, this);
}

void DataFrame::stop() {
    running = false;
    if (consumerThread.joinable()) {
        consumerThread.join();
    }
}

void DataFrame::processFrames() {
    while (running) {
        try {
            // Extrae el siguiente frame de FrameQueue
            std::vector<uint8_t> frame = frameQueue.popFrame();

            uint8_t sensorId;
            uint16_t sequenceNumber, timestamp;

            // Extraemos los datos del mensaje y el sensor ID
            cv::Mat data = extractData(frame, sensorId, sequenceNumber, timestamp);

            // Calculamos la latencia
            calculateLatency(timestamp);

            // Almacenamos los datos en DataAcquisition
            //dataAcquisition.storeData(sensorId, data);

            // Mostrar el frame de video
            cv::namedWindow("GCS", cv::WINDOW_AUTOSIZE);

            if (!data.empty()) {
                cv::imshow("GCS", data);

                // Agregar un pequeño delay para permitir cerrar la ventana correctamente
                if (cv::waitKey(1) == 27) { // Si se presiona 'Esc'
                    running = false;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error procesando frame: " << e.what() << std::endl;
        }
    }

    // Cerrar todas las ventanas al finalizar
    cv::destroyAllWindows();
}

cv::Mat DataFrame::extractData(const std::vector<uint8_t>& frame, uint8_t& sensorId, uint16_t& sequenceNumber, uint16_t& timestamp) {
    const size_t minFrameSize = 10; // Tamaño mínimo de los campos fijos
    
    // Leer Inicio de Trama (2 bytes) - ignorado para este caso
    uint16_t frameStart = (frame[0] << 8) | frame[1];
    if (frameStart != 0xABCD) {
        throw std::runtime_error("Inicio de Trama inválido.");
    }

    // Leer Número de Secuencia (2 bytes)
    sequenceNumber = (frame[2] << 8) | frame[3];

    // Leer Timestamp (2 bytes)
    timestamp = (frame[4] << 8) | frame[5];

    // Leer SensorID (1 byte)
    sensorId = frame[6];

    // Leer Estado del Sensor (1 byte) - ignorado para este caso
    uint8_t sensorStatus = frame[7];
    if (sensorStatus != 0x01) {
        throw std::runtime_error("Estado del Sensor inválido.");
    }

    // Leer Longitud de los Datos del Sensor (2 bytes)
    uint16_t dataLength = (frame[8] << 8) | frame[9];
    if (frame.size() < minFrameSize + dataLength) {
        throw std::runtime_error("Frame incompleto: datos del sensor faltantes.");
    }

    // Extraer Datos del Sensor
    std::vector<uint8_t> sensorData(frame.begin() + minFrameSize, frame.begin() + frame.size());

    // Decodificar los datos del sensor como una imagen comprimida
    cv::Mat decodedData = cv::imdecode(sensorData, cv::IMREAD_COLOR);
    if (decodedData.empty()) {
        throw std::runtime_error("Error al decodificar los datos del sensor.");
    }

    return decodedData;
}

void DataFrame::calculateLatency(uint16_t messageTimestamp) {
    static uint64_t totalLatency = 0; // Acumulador de latencia total
    static uint64_t messageCount = 0; // Contador de mensajes procesados

    // Obtener el tiempo actual en milisegundos (limitado a 2 bytes)
    uint16_t currentTimestamp = static_cast<uint16_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count() & 0xFFFF
        );

    // Calcular la latencia teniendo en cuenta el envolvimiento del timestamp
    uint16_t latency = (currentTimestamp >= messageTimestamp)
        ? (currentTimestamp - messageTimestamp)
        : (0x10000 - messageTimestamp + currentTimestamp);

    // Actualizar acumulador y contador
    totalLatency += latency;
    ++messageCount;

    // Calcular la latencia promedio
    double averageLatency = static_cast<double>(totalLatency) / messageCount;

    // Imprimir la latencia actual y promedio
    std::cout << "\rLatencia del mensaje actual: " << latency << " ms, "
        << "Latencia media: " << averageLatency << " ms ";
}