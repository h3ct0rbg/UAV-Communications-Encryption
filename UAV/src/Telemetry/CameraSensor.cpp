#include "CameraSensor.hpp"
#include <iostream>

CameraSensor::CameraSensor(DataAcquisition& acquisition, uint8_t sensorId)
    : dataAcquisition(acquisition), sensorId(sensorId), running(false) {}

void CameraSensor::start() {
    running = true;
    producerThread = std::thread(&CameraSensor::produceFrames, this);
}

void CameraSensor::stop() {
    running = false;
    if (producerThread.joinable()) {
        producerThread.join();
    }
}

void CameraSensor::produceFrames() {
    cv::VideoCapture camera(0); // Abre la cámara (dispositivo 0)
    if (!camera.isOpened()) {
        std::cerr << "ERROR: No se pudo abrir la cámara." << std::endl;
        return;
    }

    cv::namedWindow("UAV", cv::WINDOW_AUTOSIZE);

    while (running) {
        cv::Mat frame;
        camera >> frame; // Captura un frame
        if (frame.empty()) {
            std::cerr << "ERROR: Captura de frame fallida." << std::endl;
            break;
        }

        cv::imshow("UAV", frame);                   // Muestra el frame en la ventana
        dataAcquisition.storeData(sensorId, frame); // Almacena el frame en DataAcquisition

        if (cv::waitKey(10) == 27) { // Detiene si se presiona ESC
            stop();
        }

        //std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    cv::destroyWindow("Webcam");
}