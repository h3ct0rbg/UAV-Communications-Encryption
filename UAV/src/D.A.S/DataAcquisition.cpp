#include "DataAcquisition.hpp"

void DataAcquisition::storeData(uint8_t sensorId, const cv::Mat& data) {
    // Bloquea el mutex específico del sensor para operaciones en su cola
    std::unique_lock<std::mutex> lock(sensorMutexMap[sensorId]);
    sensorDataMap[sensorId].push(data.clone());           // Clona y almacena el frame en la cola correspondiente
    dataCondition.notify_one();                           // Notifica a los consumidores que hay un nuevo dato
}

cv::Mat DataAcquisition::retrieveData(uint8_t sensorId) {
    std::unique_lock<std::mutex> lock(sensorMutexMap[sensorId]);

    // Espera hasta que haya datos disponibles en la cola específica del sensor
    dataCondition.wait(lock, [this, sensorId]() {
        return !sensorDataMap[sensorId].empty();
        });

    cv::Mat data = sensorDataMap[sensorId].front();       // Obtiene el primer elemento de la cola
    sensorDataMap[sensorId].pop();                        // Elimina el elemento extraído de la cola
    return data;                                          // Retorna el dato extraído
}