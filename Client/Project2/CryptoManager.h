/**
 * @file        CryptoManager.h
 * @author      Natanel Maor Fishman
 * @brief       Cryptographic operations manager for secure messaging
 * @details     Handles RSA and AES encryption/decryption operations, key generation,
 *              key storage, and secure data handling for the messaging system.
 * @version     2.0
 * @date        2025
 */

#pragma once

#include <string>
#include "protocol.h"

// Forward declarations
class RSAPrivateWrapper;
class AESWrapper;

/**
 * @class       CryptoManager
 * @brief       Manages all cryptographic operations for secure messaging
 * @details     Centralizes encryption, decryption, key generation, and secure
 *              data handling operations. Provides abstraction layer for
 *              cryptographic operations used throughout the messaging system.
 */
class CryptoManager
{
public:
    // ================================
    // Constructor and Destructor
    // ================================

    /**
     * @brief       Default constructor
     * @details     Creates CryptoManager with uninitialized cryptographic engines
     */
    CryptoManager();

    /**
     * @brief       Virtual destructor with secure cleanup
     * @details     Ensures proper cleanup of cryptographic data and engines
     */
    virtual ~CryptoManager();

    // Copy control (deleted for security)
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager(CryptoManager&&) noexcept = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
    CryptoManager& operator=(CryptoManager&&) noexcept = delete;

    // ================================
    // RSA Operations
    // ================================

    /**
     * @brief       Generates new RSA key pair
     * @return      true if key pair generated successfully, false otherwise
     * @details     Creates new private key wrapper with fresh RSA key pair
     */
    bool generateRSAKeyPair();

    /**
     * @brief       Loads RSA private key from string
     * @param[in]   privateKey    Private key data
     * @return      true if key loaded successfully, false otherwise
     * @details     Initializes private key wrapper with provided key data
     */
    bool loadRSAPrivateKey(const std::string& privateKey);

    /**
     * @brief       Gets RSA public key
     * @return      Public key string
     * @details     Returns public key for sharing with other clients
     */
    std::string getRSAPublicKey() const;

    /**
     * @brief       Gets RSA private key
     * @return      Private key string
     * @details     Returns private key for storage or backup
     */
    std::string getRSAPrivateKey() const;

    /**
     * @brief       Decrypts data using RSA private key
     * @param[in]   data    Encrypted data buffer
     * @param[in]   size    Size of encrypted data
     * @return      Decrypted data string
     * @details     Uses private key to decrypt RSA-encrypted data
     */
    std::string decryptRSA(const uint8_t* data, size_t size) const;

    /**
     * @brief       Encrypts data using RSA public key
     * @param[in]   publicKey    Target public key
     * @param[in]   data         Data to encrypt
     * @param[in]   size         Size of data
     * @return      Encrypted data string
     * @details     Uses provided public key to encrypt data
     */
    std::string encryptRSA(const PublicKeyStruct& publicKey, const uint8_t* data, size_t size) const;

    // ================================
    // AES Operations
    // ================================

    /**
     * @brief       Generates new AES symmetric key
     * @return      Generated symmetric key structure
     * @details     Creates new random AES key for session encryption
     */
    SymmetricKeyStruct generateAESKey() const;

    /**
     * @brief       Encrypts text using AES
     * @param[in]   symmetricKey    AES key to use
     * @param[in]   plaintext       Text to encrypt
     * @return      Encrypted data string
     * @details     Encrypts string data using AES-CBC encryption
     */
    std::string encryptAES(const SymmetricKeyStruct& symmetricKey, const std::string& plaintext) const;

    /**
     * @brief       Encrypts binary data using AES
     * @param[in]   symmetricKey    AES key to use
     * @param[in]   data           Binary data to encrypt
     * @param[in]   size           Size of data
     * @return      Encrypted data string
     * @details     Encrypts binary data using AES-CBC encryption
     */
    std::string encryptAES(const SymmetricKeyStruct& symmetricKey, const uint8_t* data, size_t size) const;

    /**
     * @brief       Decrypts data using AES
     * @param[in]   symmetricKey    AES key to use
     * @param[in]   data           Encrypted data buffer
     * @param[in]   size           Size of encrypted data
     * @return      Decrypted data string
     * @details     Decrypts AES-encrypted data to original form
     */
    std::string decryptAES(const SymmetricKeyStruct& symmetricKey, const uint8_t* data, size_t size) const;

    // ================================
    // Validation Methods
    // ================================

    /**
     * @brief       Checks if RSA engine is initialized
     * @return      true if RSA engine available, false otherwise
     * @details     Validates that RSA operations are possible
     */
    bool isRSAInitialized() const;

private:
    // ================================
    // Member Variables
    // ================================

    RSAPrivateWrapper* _rsaEngine;  ///< RSA cryptographic engine

    // ================================
    // Helper Methods
    // ================================

    /**
     * @brief       Cleans up cryptographic engines
     * @details     Securely destroys cryptographic objects and clears memory
     */
    void cleanup();
};