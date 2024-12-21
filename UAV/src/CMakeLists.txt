# Archivo src/CMakeLists.txt

#############
## OpenCV  ##
#############

# Ruta del directorio de OpenCV
set(OpenCV_DIR "D:/UAH/TFG/UAV/third_party/opencv/build")
find_package(OpenCV REQUIRED)

# Incluir directorios de OpenCV
include_directories(${OpenCV_INCLUDE_DIRS})

#############
## OpenSSL ##
#############

# Ruta del directorio de OpenSSL
set(OpenSSL_DIR "D:/UAH/TFG/UAV/third_party/openssl")
find_package(OpenSSL REQUIRED)

# Incluir directorios de OpenSSL
include_directories(${OPENSSL_INCLUDE_DIRS})

################
## Executable ##
################

# Lista de archivos fuente
set(SOURCES
	    main.cpp
    	Telemetry/CameraSensor.cpp
	    D.A.S/DataAcquisition.cpp
    	D.A.S/DataFrame.cpp
    	Cipher/FrameQueue.cpp
    	Cipher/Cipher.cpp
    	Communication/Connect.cpp
    	Communication/MessageQueue.cpp
    	Communication/Sender.cpp
)

# Crear el ejecutable
add_executable(UAV ${SOURCES})

# Vincular bibliotecas al ejecutable
target_link_libraries(UAV PRIVATE ${OpenCV_LIBS} OpenSSL::SSL)

# Incluir directorios adicionales, si es necesario
target_include_directories(UAV PRIVATE ${CMAKE_SOURCE_DIR}/include)