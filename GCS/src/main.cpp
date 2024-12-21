#include "Communication/Connect.hpp"
#include "Communication/MessageQueue.hpp"
#include "Communication/Receiver.hpp"
#include "D.A.S/DataAcquisition.hpp"
#include "D.A.S/DataFrame.hpp"
#include "Cypher/Decipher.hpp"
#include <mutex>

std::mutex mtx;
std::condition_variable conditionVar;

static void waitIndefinitely() {
    std::unique_lock<std::mutex> lock(mtx);
    conditionVar.wait(lock);  // Espera indefinida
}

int main() {
    // Ajustar el nivel de log a errores únicamente
    cv::utils::logging::setLogLevel(cv::utils::logging::LOG_LEVEL_ERROR);

    // Configuración de puerto en escucha
    uint16_t port = 12345;

    // Colas compartidas
    DataAcquisition dataAcquisition;
    FrameQueue frameQueue;
    MessageQueue messageQueue;

    // Inicializar Conexión
    Connect connection(port);
    try {
        connection.initTCPConnection();         // Inicializar Conexión TCP
        connection.exchangeCertificates();      // Intercambiar CA
        connection.genKey();                    // Generar clave de cifrado
        connection.closeTCPConnection();        // Cerrar Conexión TCP
        connection.initUDPConnection();         // Inicializar Conexión UDP
    }
    catch (const std::exception& e) {
        std::cerr << "Error en la conexion: " << e.what() << std::endl;
        return -1;
    }

    // Inicializar Modulo de Comunicación
    Receiver receiver(messageQueue, connection.getListenSock());

    // Inicializar Modulo de Cifrado
    Decipher decipher(connection.getDerivedKey(), messageQueue, frameQueue);

    // Inicializar Modulo de Adquisición de Datos
    DataFrame dataFrame(dataAcquisition, frameQueue);

    // Inicializar los procesos
    receiver.start();
    decipher.start();
    dataFrame.start();
 
    // Mantiene el programa en ejecución indefinidamente
    std::thread infiniteWaitThread(waitIndefinitely);

    // Espera a que el hilo indefinido termine
    infiniteWaitThread.join();

    // Detiene los procesos al salir
    receiver.stop();
    decipher.stop();
    dataFrame.stop();

    // Cierra la conexión al finalizar
    connection.closeUDPConnection();
    return 0;
}