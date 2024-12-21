# Mínima versión requerida de CMake
cmake_minimum_required(VERSION 3.29)

# Nombre del proyecto y estándar de C++
project(GCS VERSION 1.0 LANGUAGES CXX)

# Establecer el estándar de C++
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Variables de configuración
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Tipo de build: Debug o Release")
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)

# Directorios de salida para binarios y bibliotecas
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Incluir subdirectorios
add_subdirectory(src)       # Código fuente principal
# add_subdirectory(tests)     # Código para pruebas unitarias

# Dependencias externas
add_subdirectory(third_party)