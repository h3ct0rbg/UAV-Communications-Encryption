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
    // Ajustar el nivel de log a errores �nicamente
    cv::utils::logging::setLogLevel(cv::utils::logging::LOG_LEVEL_ERROR);

    // Configuraci�n de puerto en escucha
    uint16_t port = 12345;

    // Colas compartidas
    DataAcquisition dataAcquisition;
    FrameQueue frameQueue;
    MessageQueue messageQueue;

    // Inicializar Conexi�n
    Connect connection(port);
    try {
        connection.initTCPConnection();         // Inicializar Conexi�n TCP
        connection.exchangeCertificates();      // Intercambiar CA
        connection.genKey();                    // Generar clave de cifrado
        connection.closeTCPConnection();        // Cerrar Conexi�n TCP
        connection.initUDPConnection();         // Inicializar Conexi�n UDP
    }
    catch (const std::exception& e) {
        std::cerr << "Error en la conexion: " << e.what() << std::endl;
        return -1;
    }

    // Inicializar Modulo de Comunicaci�n
    Receiver receiver(messageQueue, connection.getListenSock());

    // Inicializar Modulo de Cifrado
    Decipher decipher(connection.getDerivedKey(), messageQueue, frameQueue);

    // Inicializar Modulo de Adquisici�n de Datos
    DataFrame dataFrame(dataAcquisition, frameQueue);

    // Inicializar los procesos
    receiver.start();
    decipher.start();
    dataFrame.start();
 
    // Mantiene el programa en ejecuci�n indefinidamente
    std::thread infiniteWaitThread(waitIndefinitely);

    // Espera a que el hilo indefinido termine
    infiniteWaitThread.join();

    // Detiene los procesos al salir
    receiver.stop();
    decipher.stop();
    dataFrame.stop();

    // Cierra la conexi�n al finalizar
    connection.closeUDPConnection();
    return 0;
}