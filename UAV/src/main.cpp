#include "Telemetry/CameraSensor.hpp"
#include "D.A.S/DataAcquisition.hpp"
#include "D.A.S/DataFrame.hpp"
#include "Cipher/Cipher.hpp"
#include "Cipher/FrameQueue.hpp"
#include "Communication/Connect.hpp"
#include "Communication/MessageQueue.hpp"
#include "Communication/Sender.hpp"

std::mutex mtx;
std::condition_variable conditionVar;

static void waitIndefinitely() {
    std::unique_lock<std::mutex> lock(mtx);
    conditionVar.wait(lock);  // Espera indefinida
}

int main() {
    // Ajustar el nivel de log a errores únicamente
    cv::utils::logging::setLogLevel(cv::utils::logging::LOG_LEVEL_ERROR);

    // Configuración de ip y puerto
    std::string ip = "127.0.0.1";
    uint16_t port = 12345;

    // Colas compartidas
    DataAcquisition dataAcquisition;
    FrameQueue frameQueue;
    MessageQueue messageQueue;

    // Inicializar Conexión
    Connect connection(port, ip);
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

    // Inicializar Modulo de Telemetría
    CameraSensor camera(dataAcquisition, 0x01);

    // Inicializar Modulo de Adquisición de Datos
    DataFrame dataFrame(dataAcquisition, 0x01, frameQueue);

    // Inicializar Modulo de Cifrado
    Cipher Cipher(frameQueue, messageQueue, connection.getDerivedKey());

    // Inicializar Modulo de Comunicación
    Sender sender(messageQueue, connection.getSendSock());

    // Inicializar los procesos
    camera.start();
    dataFrame.start();
    Cipher.start();
    sender.start();
 
    // Mantiene el programa en ejecución indefinidamente
    std::thread infiniteWaitThread(waitIndefinitely);

    // Espera a que el hilo indefinido termine
    infiniteWaitThread.join();

    // Detiene los procesos al salir
    camera.start();
    dataFrame.stop();
    Cipher.stop();
    sender.stop();

    // Cierra la conexión al finalizar
    connection.closeUDPConnection();
    return 0;
}