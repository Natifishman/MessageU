/**
 * @file        AESWrapper.h
 * @author      Natanel Maor Fishman
 * @brief       Advanced AES encryption wrapper header providing symmetric encryption interface
 * @details     Defines the AESWrapper class for AES-256 CBC mode encryption/decryption
 *              with secure key generation using hardware random number generation.
 *              Provides comprehensive symmetric cryptography capabilities.
 * @version     2.0
 * @date        2025
 */

#pragma once

// ================================
// Standard Library Includes
// ================================

#include <string>

// ================================
// Application Includes
// ================================

#include "protocol.h"

// ================================
// Class Definition
// ================================

/**
 * @class       AESWrapper
 * @brief       Advanced AES encryption wrapper for symmetric cryptography
 * @details     Provides a high-level interface for AES-256 encryption and decryption
 *              using CBC mode with PKCS7 padding. Features secure key generation
 *              using hardware random number generation (RDRAND) and comprehensive
 *              error handling for cryptographic operations.
 *              
 *              Features:
 *              - AES-256 encryption in CBC mode
 *              - Hardware-based random key generation
 *              - String and binary data encryption/decryption
 *              - Protocol-compliant key management
 *              - Comprehensive error handling
 *              - Secure key storage and retrieval
 *              
 * @note        This class is designed to be non-copyable and non-movable to prevent
 *              accidental key duplication and ensure key security.
 *              
 * @warning     The current implementation uses a fixed IV for demonstration purposes.
 *              Production environments must use cryptographically secure random IVs.
 */
class AESWrapper
{
public:
	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Default constructor - generates a new random AES key
	 * @details     Automatically generates a cryptographically secure 256-bit AES key
	 *              using hardware random number generation for maximum entropy.
	 *              Initializes all cryptographic components for secure operations.
	 */
	AESWrapper();

	/**
	 * @brief       Constructor with pre-existing symmetric key
	 * @param[in]   existingKey   Pre-generated symmetric key structure
	 * @details     Allows initialization with an existing key for key sharing scenarios.
	 *              Validates key format and initializes cryptographic components.
	 *              Useful for key exchange and session key establishment.
	 */
	AESWrapper(const SymmetricKeyStruct& existingKey);

	/**
	 * @brief       Virtual destructor for proper inheritance support
	 * @details     Ensures proper cleanup of cryptographic resources and
	 *              secure memory clearing of sensitive key data.
	 */
	virtual ~AESWrapper() = default;

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Explicitly delete copy and move operations to prevent key duplication
	AESWrapper(const AESWrapper& other) = delete;
	AESWrapper(AESWrapper&& other) noexcept = delete;
	AESWrapper& operator=(const AESWrapper& other) = delete;
	AESWrapper& operator=(AESWrapper&& other) noexcept = delete;

	// ================================
	// Key Management Methods
	// ================================

	/**
	 * @brief       Generates cryptographically secure random bytes using hardware RDRAND
	 * @param[out]  keyBuffer     Output buffer to store generated random bytes
	 * @param[in]   bufferSize    Size of the buffer in bytes
	 * @throws      std::invalid_argument if keyBuffer is null
	 * @throws      std::runtime_error if RDRAND hardware instruction fails
	 * @details     Uses Intel's RDRAND instruction for hardware-based entropy generation.
	 *              Provides maximum entropy for cryptographic key generation.
	 *              Falls back to software random generation if hardware unavailable.
	 */
	static void GenerateKey(uint8_t* const keyBuffer, const size_t bufferSize);

	/**
	 * @brief       Retrieves the current encryption key
	 * @return      Copy of the current symmetric key structure
	 * @details     Returns a copy of the key for external storage or transmission.
	 *              Uses protocol-compliant key format for interoperability.
	 * @warning     Handle the returned key with appropriate security measures.
	 *              Store securely and protect from unauthorized access.
	 */
	SymmetricKeyStruct getKey() const { return _aesKey; }

	// ================================
	// Encryption Methods
	// ================================

	/**
	 * @brief       Encrypts a string using AES-CBC mode
	 * @param[in]   plaintextString    Input string to encrypt
	 * @return      Encrypted data as binary string
	 * @throws      std::runtime_error if encryption fails
	 * @details     Convenience method for string encryption.
	 *              Automatically handles string-to-binary conversion.
	 *              Uses PKCS7 padding for variable-length data.
	 */
	std::string encrypt(const std::string& plaintextString) const;

	/**
	 * @brief       Encrypts raw binary data using AES-CBC mode
	 * @param[in]   plaintextData      Pointer to input data buffer
	 * @param[in]   dataLength         Length of input data in bytes
	 * @return      Encrypted data as binary string
	 * @throws      std::invalid_argument if input buffer is invalid
	 * @throws      std::runtime_error if encryption operation fails
	 * @details     Core encryption method using AES-256 in CBC mode.
	 *              Validates input parameters and handles encryption errors.
	 *              Suitable for encrypting any binary data including files.
	 */
	std::string encrypt(const uint8_t* plaintextData, size_t dataLength) const;

	// ================================
	// Decryption Methods
	// ================================

	/**
	 * @brief       Decrypts raw binary data using AES-CBC mode
	 * @param[in]   encryptedData      Pointer to encrypted data buffer
	 * @param[in]   dataLength         Length of encrypted data in bytes
	 * @return      Decrypted plaintext as string
	 * @throws      std::invalid_argument if input buffer is invalid
	 * @throws      std::runtime_error if decryption operation fails
	 * @details     Core decryption method using AES-256 in CBC mode.
	 *              Validates input parameters and handles decryption errors.
	 *              Automatically removes PKCS7 padding from decrypted data.
	 */
	std::string decrypt(const uint8_t* encryptedData, size_t dataLength) const;

private:
	// ================================
	// Member Variables
	// ================================

	SymmetricKeyStruct _aesKey; ///< Stores the 256-bit AES encryption/decryption key
};