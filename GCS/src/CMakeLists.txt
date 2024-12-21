# Archivo src/CMakeLists.txt

#############
## OpenCV  ##
#############

# Ruta del directorio de OpenCV
set(OpenCV_DIR "D:/UAH/TFG/GCS/third_party/opencv/build")
find_package(OpenCV REQUIRED)

# Incluir directorios de OpenCV
include_directories(${OpenCV_INCLUDE_DIRS})

#############
## OpenSSL ##
#############

# Ruta del directorio de OpenSSL
set(OpenSSL_DIR "D:/UAH/TFG/GCS/third_party/openssl")
find_package(OpenSSL REQUIRED)

# Incluir directorios de OpenSSL
include_directories(${OPENSSL_INCLUDE_DIRS})

################
## Executable ##
################

# Lista de archivos fuente
set(SOURCES
	main.cpp
	D.A.S/DataAcquisition.cpp
    D.A.S/DataFrame.cpp
    Cypher/FrameQueue.cpp
    Cypher/Decipher.cpp
    Communication/Connect.cpp
    Communication/MessageQueue.cpp
    Communication/Receiver.cpp
)

# Crear el ejecutable
add_executable(GCS ${SOURCES})

# Vincular bibliotecas al ejecutable
target_link_libraries(GCS PRIVATE ${OpenCV_LIBS} OpenSSL::SSL)

# Incluir directorios adicionales, si es necesario
target_include_directories(GCS PRIVATE ${CMAKE_SOURCE_DIR}/include)