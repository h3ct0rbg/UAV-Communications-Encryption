#ifndef DATAFRAME_HPP
#define DATAFRAME_HPP

#include "DataAcquisition.hpp"
#include "../Cipher/FrameQueue.hpp"
#include <vector>
#include <thread>
#include <atomic>
#include <cstdint>

class DataFrame {
public:
    DataFrame(DataAcquisition& acquisition, uint8_t sensorId, FrameQueue& frameQueue);
    void start(); // Inicia el consumo de frames
    void stop();  // Detiene el consumo de frames

private:
    void createFrame(); // Extrae frames y crea tramas de datos
    DataAcquisition& dataAcquisition;
    FrameQueue& frameQueue;
    uint8_t sensorId;
    std::thread consumerThread;
    std::atomic<bool> running;
};

#endif // DATAFRAME_HPP