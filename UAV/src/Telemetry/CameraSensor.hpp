#ifndef CAMERASENSOR_HPP
#define CAMERASENSOR_HPP

#include <opencv2/opencv.hpp>
#include "../D.A.S/DataAcquisition.hpp"
#include <thread>
#include <atomic>

class CameraSensor {
public:
    CameraSensor(DataAcquisition& acquisition, uint8_t sensorId);
    void start(); // Inicia la producci�n de frames y la visualizaci�n de video
    void stop();  // Detiene la producci�n de frames

private:
    void produceFrames(); // Produce, almacena y muestra frames en DataAcquisition
    DataAcquisition& dataAcquisition;
    uint8_t sensorId;
    std::thread producerThread;
    std::atomic<bool> running;
};

#endif // CAMERASENSOR_HPP