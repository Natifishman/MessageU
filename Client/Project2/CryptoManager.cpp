/**
 * @file        CryptoManager.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of cryptographic operations manager
 * @details     Provides secure encryption/decryption operations using RSA and AES
 *              algorithms with proper key management and error handling.
 * @date        2025
 */

#include "CryptoManager.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include <cstring>

// ================================
// Constructor and Destructor
// ================================

CryptoManager::CryptoManager() : _rsaEngine(nullptr)
{
    // Initialize with clean state
}

CryptoManager::~CryptoManager()
{
    cleanup();
}

// ================================
// RSA Operations
// ================================

bool CryptoManager::generateRSAKeyPair()
{
    try {
        // Clean up existing engine before creating new one
        delete _rsaEngine;
        _rsaEngine = new RSAPrivateWrapper();
        return true;
    }
    catch (...) {
        _rsaEngine = nullptr;
        return false;
    }
}

bool CryptoManager::loadRSAPrivateKey(const std::string& privateKey)
{
    if (privateKey.empty()) {
        return false;
    }

    try {
        // Clean up existing engine before creating new one
        delete _rsaEngine;
        _rsaEngine = new RSAPrivateWrapper(privateKey);
        return true;
    }
    catch (...) {
        _rsaEngine = nullptr;
        return false;
    }
}

std::string CryptoManager::getRSAPublicKey() const
{
    if (!_rsaEngine) {
        return "";
    }

    try {
        return _rsaEngine->getPublicKey();
    }
    catch (...) {
        return "";
    }
}

std::string CryptoManager::getRSAPrivateKey() const
{
    if (!_rsaEngine) {
        return "";
    }

    try {
        return _rsaEngine->getPrivateKey();
    }
    catch (...) {
        return "";
    }
}

std::string CryptoManager::decryptRSA(const uint8_t* data, size_t size) const
{
    if (!_rsaEngine || !data || size == 0) {
        return "";
    }

    try {
        return _rsaEngine->decrypt(data, size);
    }
    catch (...) {
        return "";
    }
}

std::string CryptoManager::encryptRSA(const PublicKeyStruct& publicKey, const uint8_t* data, size_t size) const
{
    if (!data || size == 0) {
        return "";
    }

    try {
        RSAPublicWrapper rsa(publicKey);
        return rsa.encrypt(data, size);
    }
    catch (...) {
        return "";
    }
}

// ================================
// AES Operations
// ================================

SymmetricKeyStruct CryptoManager::generateAESKey() const
{
    SymmetricKeyStruct keyStruct;
    memset(&keyStruct, 0, sizeof(keyStruct));

    try {
        AESWrapper aes;
        keyStruct = aes.getKey();
    }
    catch (...) {
        // Return zeroed key structure on error
    }

    return keyStruct;
}

std::string CryptoManager::encryptAES(const SymmetricKeyStruct& symmetricKey, const std::string& plaintext) const
{
    if (plaintext.empty()) {
        return "";
    }

    try {
        AESWrapper aes(symmetricKey);
        return aes.encrypt(plaintext);
    }
    catch (...) {
        return "";
    }
}

std::string CryptoManager::encryptAES(const SymmetricKeyStruct& symmetricKey, const uint8_t* data, size_t size) const
{
    if (!data || size == 0) {
        return "";
    }

    try {
        AESWrapper aes(symmetricKey);
        return aes.encrypt(data, size);
    }
    catch (...) {
        return "";
    }
}

std::string CryptoManager::decryptAES(const SymmetricKeyStruct& symmetricKey, const uint8_t* data, size_t size) const
{
    if (!data || size == 0) {
        return "";
    }

    try {
        AESWrapper aes(symmetricKey);
        return aes.decrypt(data, size);
    }
    catch (...) {
        return "";
    }
}

// ================================
// Validation Methods
// ================================

bool CryptoManager::isRSAInitialized() const
{
    return (_rsaEngine != nullptr);
}

// ================================
// Helper Methods
// ================================

void CryptoManager::cleanup()
{
    if (_rsaEngine) {
        delete _rsaEngine;
        _rsaEngine = nullptr;
    }
}