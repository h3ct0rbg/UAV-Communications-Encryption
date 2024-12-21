#ifndef DATAFRAME_HPP
#define DATAFRAME_HPP

#include "../Cypher/FrameQueue.hpp"
#include "DataAcquisition.hpp"
#include <thread>
#include <atomic>
#include <vector>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <opencv2/opencv.hpp>

class DataFrame {
public:
    DataFrame(DataAcquisition& acquisition, FrameQueue& frameQueue);
    ~DataFrame();

    void start(); // Inicia el procesamiento de tramas
    void stop();  // Detiene el procesamiento

private:
    DataAcquisition& dataAcquisition;
    FrameQueue& frameQueue;
    std::atomic<bool> running; // Control de ejecución
    std::thread consumerThread;

    void processFrames(); // Procesa las tramas de FrameQueue

    // Extrae los datos del mensaje según el formato especificado
    cv::Mat extractData(const std::vector<uint8_t>& frame, uint8_t& sensorId, uint16_t& sequenceNumber, uint16_t& timestamp);

    // Calcula la latencia del mensaje
    void calculateLatency(uint16_t messageTimestamp);
};

#endif // DATAFRAME_HPP