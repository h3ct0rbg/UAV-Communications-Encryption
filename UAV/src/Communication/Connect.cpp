#include "Connect.hpp"

Connect::Connect(uint16_t port, const std::string& serverIP)
    : port(port), serverIP(serverIP), sendSockfd(-1), sslCtx(nullptr), ssl(nullptr) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("Error inicializando Winsock.");
    }
#endif
}

Connect::~Connect() {
    closeTCPConnection();
    closeUDPConnection();
#ifdef _WIN32
    WSACleanup();
#endif
}

bool Connect::initTCPConnection() {
    // Crear el socket TCP
    sendSockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sendSockfd < 0) {
        std::cerr << "Error al crear el socket TCP." << std::endl;
        return false;
    }

    // Configurar la dirección del servidor
    sockaddr_in serverAddress = {};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);

    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr) <= 0) {
        std::cerr << "Error al convertir la dirección IP." << std::endl;
        closeTCPConnection();
        return false;
    }

    // Intentar conectarse al servidor con reintentos
    const int maxRetries = 10;
    const int retryDelaySeconds = 3;
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        if (connect(sendSockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == 0) {
            std::cout << "\nConexion TCP establecida con el GCS" << std::endl;
            return true;
        }

        std::cerr << "\rConectando... intento " << attempt << " / " << maxRetries;
#ifdef _WIN32
        Sleep(retryDelaySeconds * 1000);
#else
        sleep(retryDelaySeconds);
#endif
    }

    std::cerr << "No se pudo establecer la conexion TCP con el GCS tras " << maxRetries << " intentos." << std::endl;
    closeTCPConnection();
    return false;
}

void Connect::closeTCPConnection() {
    if (sendSockfd >= 0) {
#ifdef _WIN32
        closesocket(sendSockfd);
#else
        close(sendSockfd);
#endif
        sendSockfd = -1;
        std::cout << "Conexion TCP cerrada.\n" << std::endl;
    }
}

bool Connect::initUDPConnection() {
#ifdef _WIN32
    // Inicializar Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Error al inicializar Winsock: " << WSAGetLastError() << std::endl;
        return false;
    }
#endif

    // Crear el socket UDP
    sendSockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sendSockfd < 0) {
        std::cerr << "Error al crear el socket UDP" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    // Configurar la dirección del servidor
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Error al convertir la IP del servidor" << std::endl;
        closeUDPConnection();
        return false;
    }

    // Conectar al servidor (en UDP, esto es opcional, pero configura el destino predeterminado para send())
    if (connect(sendSockfd, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        std::cerr << "Error al conectar con el servidor UDP" << std::endl;
        closeUDPConnection();
        return false;
    }

    std::cerr << "Socket UDP inicializado para enviar datos" << std::endl;

    return true;
    }

void Connect::closeUDPConnection() {
    if (sendSockfd >= 0) {
#ifdef _WIN32
        closesocket(sendSockfd);
        WSACleanup();
#else
        close(sendSockfd);
#endif
        sendSockfd = -1;
    }
}

bool Connect::exchangeCertificates() {
    try {
        // Rutas de los certificados
        std::string ca_cert_path = "../../../src/Communication/Certificates/ca_cert.pem";
        std::string uav_cert_path = "../../../src/Communication/Certificates/uav_cert.pem";
        std::string uav_key_path = "../../../src/Communication/Certificates/uav_key.pem";

        // Crear el contexto SSL
        sslCtx = SSL_CTX_new(TLSv1_2_client_method());
        if (!sslCtx) {
            throw std::runtime_error("Error creando contexto SSL.");
        }

        // Configurar el certificado y clave privada
        if (SSL_CTX_use_certificate_file(sslCtx, uav_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(sslCtx, uav_key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            throw std::runtime_error("Error configurando certificado o clave privada.");
        }

        // Cargar el certificado de la autoridad certificadora (CA)
        if (!SSL_CTX_load_verify_locations(sslCtx, ca_cert_path.c_str(), nullptr)) {
            throw std::runtime_error("Error cargando el certificado de la autoridad certificadora (CA).");
        }

        // Establecer política de verificación de certificados
        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER, nullptr);

        // Establecer conexión SSL sobre el socket TCP
        ssl = SSL_new(sslCtx);
        SSL_set_fd(ssl, sendSockfd);

        if (SSL_connect(ssl) <= 0) {
            throw std::runtime_error("Error inicializando la conexion SSL.");
        }

        std::cout << "Conexion SSL establecida con el GCS." << std::endl;

        // Verificar el certificado del servidor
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            throw std::runtime_error("El certificado del servidor no es valido.");
        }

        std::cout << "El certificado del servidor es valido." << std::endl;

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
}

void Connect::genKey() {
    EC_GROUP* ecGroup = nullptr;
    EC_KEY* localKey = nullptr;
    EC_POINT* remotePubKey = nullptr;
    EVP_PKEY_CTX* pctx = nullptr;
    size_t keyLength = 32;
    std::vector<uint8_t> derivedKey(keyLength); // Tamaño de la clave derivada en bytes (256 bits)

    try {
        // Crear un grupo EC (curva SECP256R1)
        ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecGroup) {
            throw std::runtime_error("Error creando el grupo EC.");
        }

        // Generar clave privada y pública local
        localKey = EC_KEY_new();
        if (!localKey || !EC_KEY_set_group(localKey, ecGroup) || !EC_KEY_generate_key(localKey)) {
            throw std::runtime_error("Error generando clave local ECDH.");
        }

        // Obtener la clave pública local
        const EC_POINT* localPubKey = EC_KEY_get0_public_key(localKey);
        if (!localPubKey) {
            throw std::runtime_error("Error obteniendo clave pública local.");
        }

        // Serializar la clave pública local para enviarla al otro extremo
        size_t pubKeySize = EC_POINT_point2oct(ecGroup, localPubKey, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
        std::vector<uint8_t> localPubKeyBuffer(pubKeySize);
        EC_POINT_point2oct(ecGroup, localPubKey, POINT_CONVERSION_UNCOMPRESSED, localPubKeyBuffer.data(), pubKeySize, nullptr);

        // Enviar la clave pública al otro extremo
        if (SSL_write(ssl, localPubKeyBuffer.data(), pubKeySize) <= 0) {
            throw std::runtime_error("Error enviando clave pública local.");
        }

        // Recibir la clave pública del otro extremo
        std::vector<uint8_t> remotePubKeyBuffer(pubKeySize);
        if (SSL_read(ssl, remotePubKeyBuffer.data(), pubKeySize) <= 0) {
            throw std::runtime_error("Error recibiendo clave pública remota.");
        }

        // Reconstruir la clave pública remota
        remotePubKey = EC_POINT_new(ecGroup);
        if (!remotePubKey || !EC_POINT_oct2point(ecGroup, remotePubKey, remotePubKeyBuffer.data(), pubKeySize, nullptr)) {
            throw std::runtime_error("Error reconstruyendo clave pública remota.");
        }

        // Generar clave compartida
        std::vector<uint8_t> sharedSecret(EC_GROUP_get_degree(ecGroup) / 8);
        int sharedSecretSize = ECDH_compute_key(sharedSecret.data(), sharedSecret.size(), remotePubKey, localKey, nullptr);
        if (sharedSecretSize <= 0) {
            throw std::runtime_error("Error generando clave compartida.");
        }
        sharedSecret.resize(sharedSecretSize);

        // Derivar clave usando HKDF
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx || EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0 || // Sin salt explícito
            EVP_PKEY_CTX_set1_hkdf_key(pctx, sharedSecret.data(), sharedSecret.size()) <= 0 ||
            EVP_PKEY_derive(pctx, derivedKey.data(), &keyLength) <= 0) {
            throw std::runtime_error("Error derivando clave HKDF.");
        }

        std::cout << "Clave derivada generada exitosamente." << std::endl;

    }
    catch (const std::exception& e) {
        // Liberar recursos en caso de error
        if (localKey) EC_KEY_free(localKey);
        if (ecGroup) EC_GROUP_free(ecGroup);
        if (remotePubKey) EC_POINT_free(remotePubKey);
        if (pctx) EVP_PKEY_CTX_free(pctx);

        std::cerr << "Error en la función genKey: " << e.what() << std::endl;
    }

    Connect::derivedKey = derivedKey;
}

const int& Connect::getSendSock() const {
    return sendSockfd;
}

std::vector<uint8_t> Connect::getDerivedKey() {
    if (derivedKey.empty()) {
        throw std::runtime_error("La clave derivada no se ha inicializado. Llama a genKey() primero.");
    }
    return derivedKey;
}