#include "Connect.hpp"

Connect::Connect(uint16_t port)
    : port(port), listenSockfd(-1), clientSockfd(-1), sslCtx(nullptr), ssl(nullptr) {
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
    // Crear el socket de escucha TCP
    listenSockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSockfd < 0) {
        std::cerr << "Error al crear el socket de escucha." << std::endl;
        return false;
    }

    // Configurar la dirección del servidor (GCS)
    sockaddr_in serverAddress = {};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    // Vincular el socket a la dirección y puerto
    if (bind(listenSockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Error al vincular el socket al puerto." << std::endl;
        closeTCPConnection();
        return false;
    }

    // Comenzar a escuchar conexiones entrantes
    if (listen(listenSockfd, 1) < 0) {
        std::cerr << "Error al poner el socket en modo escucha." << std::endl;
        closeTCPConnection();
        return false;
    }

    std::cout << "Esperando conexion del UAV en el puerto " << port << "..." << std::endl;

    // Aceptar la conexión entrante del UAV
    sockaddr_in clientAddress = {};
    socklen_t clientLen = sizeof(clientAddress);
    clientSockfd = accept(listenSockfd, (struct sockaddr*)&clientAddress, &clientLen);
    if (clientSockfd < 0) {
        std::cerr << "Error al aceptar la conexion." << std::endl;
        closeTCPConnection();
        return false;
    }

    std::cout << "\rConexion TCP establecida!\n" << std::endl;
    return true;
}

void Connect::closeTCPConnection() {
    if (clientSockfd >= 0) {
#ifdef _WIN32
        closesocket(clientSockfd);
#else
        close(clientSockfd);
#endif
        clientSockfd = -1;
        std::cout << "Conexion TCP con el UAV cerrada." << std::endl;
    }

    if (listenSockfd >= 0) {
#ifdef _WIN32
        closesocket(listenSockfd);
#else
        close(listenSockfd);
#endif
        listenSockfd = -1;
        std::cout << "Socket TCP de escucha cerrado.\n" << std::endl;
    }
}

bool Connect::initUDPConnection() {
    listenSockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenSockfd < 0) {
        std::cerr << "Error al crear el socket UDP" << std::endl;
        return false;
    }

    sockaddr_in serverAddress = {};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (bind(listenSockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Error al vincular el socket UDP al puerto" << std::endl;
        closeUDPConnection();
        return false;
    }

    std::cout << "Socket UDP inicializado para recibir datos" << std::endl;
    return true;
}

void Connect::closeUDPConnection() {
    if (listenSockfd >= 0) {
#ifdef _WIN32
        closesocket(listenSockfd);
#else
        close(listenSockfd);
#endif
        listenSockfd = -1;
        std::cout << "Conexion UDP con el UAV cerrada." << std::endl;
    }
    else {
        std::cerr << "No hay un socket UDP activo para cerrar." << std::endl;
    }
}

bool Connect::exchangeCertificates() {
    try {
        // Rutas de los certificados
        std::string ca_cert_path = "../../../src/Communication/Certificates/ca_cert.pem";
        std::string gcs_cert_path = "../../../src/Communication/Certificates/gcs_cert.pem";
        std::string gcs_key_path = "../../../src/Communication/Certificates/gcs_key.pem";

        // Crear el contexto SSL
        sslCtx = SSL_CTX_new(TLSv1_2_server_method());
        if (!sslCtx) {
            throw std::runtime_error("Error creando contexto SSL.");
        }

        // Configurar el certificado y clave privada
        if (SSL_CTX_use_certificate_file(sslCtx, gcs_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(sslCtx, gcs_key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
            throw std::runtime_error("Error configurando certificado o clave privada.");
        }

        // Cargar el certificado de la autoridad certificadora (CA)
        if (!SSL_CTX_load_verify_locations(sslCtx, ca_cert_path.c_str(), nullptr)) {
            throw std::runtime_error("Error cargando el certificado de la autoridad certificadora (CA).");
        }

        // Establecer política de verificación de certificados
        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

        // Verificar si la clave privada corresponde al certificado
        if (SSL_CTX_check_private_key(sslCtx) != 1) {
            throw std::runtime_error("Clave privada no corresponde al certificado.");
        }

        // Establecer conexión SSL sobre el socket TCP
        ssl = SSL_new(sslCtx);
        SSL_set_fd(ssl, clientSockfd);

        if (SSL_accept(ssl) <= 0) {
            throw std::runtime_error("Error inicializando la conexion SSL.");
        }

        std::cout << "Conexion SSL establecida con exito." << std::endl;

        // Verificar automáticamente el certificado del cliente
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            throw std::runtime_error("El certificado del cliente no es valido.");
        }

        std::cout << "El certificado del cliente es valido." << std::endl;

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

const int& Connect::getListenSock() const {
    return listenSockfd;
}

const int& Connect::getClientSock() const {
    return clientSockfd;
}

std::vector<uint8_t> Connect::getDerivedKey() {
    try {
        if (derivedKey.empty()) {
            throw std::runtime_error("La clave derivada no se ha inicializado. Llama a genKey() primero.");
        }
        return derivedKey;
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Error en getDerivedKey: " << e.what() << std::endl;
        throw;  // Vuelve a lanzar la excepción para que el llamador pueda manejarla
    }
}