#ifndef DATAACQUISITION_HPP
#define DATAACQUISITION_HPP

#include <opencv2/opencv.hpp>
#include <condition_variable>
#include <map>
#include <queue>
#include <cstdint>
#include <mutex>

class DataAcquisition {
public:
    void storeData(uint8_t sensorId, const cv::Mat& data); // Productor: Almacena datos en la cola
    cv::Mat retrieveData(uint8_t sensorId);                // Consumidor: Extrae datos de la cola

private:
    std::map<uint8_t, std::queue<cv::Mat>> sensorDataMap;  // Colas de datos para cada sensor
    std::map<uint8_t, std::mutex> sensorMutexMap;          // Mutex individual para cada sensor
    std::condition_variable dataCondition;                 // Condition variable para sincronización
};

#endif // DATAACQUISITION_HPP