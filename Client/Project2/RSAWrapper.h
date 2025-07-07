/**
 * @file        RSAWrapper.h
 * @author      Natanel Maor Fishman
 * @brief       RSA asymmetric encryption wrapper providing public/private key cryptography
 * @details     Implements RSA-1024 encryption/decryption using OAEP padding with SHA-1
 *              for secure key exchange and digital signatures.
 *              Provides comprehensive RSA key management and cryptographic operations.
 * @version     2.0
 * @date        2025
 * @warning     RSA-1024 is used for demonstration. Production environments should use
 *              RSA-2048 or higher for adequate security levels.
 */

#pragma once

// ================================
// Standard Library Includes
// ================================

#include <string>

// ================================
// Third-Party Includes
// ================================

#include <rsa.h>
#include <osrng.h>

// ================================
// Application Includes
// ================================

#include "protocol.h"

// ================================
// Constants
// ================================

/// RSA key size in bits for cryptographic operations
static constexpr size_t RSA_KEY_SIZE_BITS = 1024;

// ================================
// Class Definitions
// ================================

/**
 * @class       RSAPublicWrapper
 * @brief       RSA public key wrapper for encryption operations
 * @details     Handles RSA public key operations including data encryption.
 *              Uses OAEP padding with SHA-1 for secure encryption.
 *              This class is non-copyable and non-movable to prevent key duplication.
 *              
 *              Features:
 *              - Public key encryption with OAEP padding
 *              - Secure random number generation
 *              - Input validation and error handling
 *              - Protocol-compliant key sizes
 *              
 * @note        This class is non-copyable and non-movable to prevent key duplication
 *              and ensure cryptographic security.
 */
class RSAPublicWrapper
{
public:
	// ================================
	// Constants
	// ================================

	/// Size of public key in bytes, matching protocol specification
	static constexpr size_t PUBLIC_KEY_SIZE_BYTES = PUBLIC_KEY_LENGTH;

	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Constructor with existing public key
	 * @param[in]   publicKeyData    Pre-generated public key structure
	 * @details     Loads an existing public key for encryption operations.
	 *              Validates key format and initializes cryptographic components.
	 */
	RSAPublicWrapper(const PublicKeyStruct& publicKeyData);

	/**
	 * @brief       Virtual destructor for proper inheritance support
	 * @details     Ensures proper cleanup of cryptographic resources.
	 */
	virtual ~RSAPublicWrapper() = default;

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Explicitly delete copy and move operations to prevent key duplication
	RSAPublicWrapper(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper(RSAPublicWrapper&& other) noexcept = delete;
	RSAPublicWrapper& operator=(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper& operator=(RSAPublicWrapper&& other) noexcept = delete;

	// ================================
	// Public Interface Methods
	// ================================

	/**
	 * @brief       Encrypts data using RSA public key with OAEP padding
	 * @param[in]   plaintextData    Pointer to data to encrypt
	 * @param[in]   dataLength       Length of data in bytes
	 * @return      Encrypted data as binary string
	 * @throws      CryptoPP::Exception if encryption fails
	 * @details     Uses RSAES-OAEP-SHA encryption scheme for secure data protection.
	 *              Validates input parameters and handles encryption errors.
	 *              Suitable for encrypting symmetric keys and small data blocks.
	 */
	std::string encrypt(const uint8_t* plaintextData, size_t dataLength);

private:
	// ================================
	// Member Variables
	// ================================

	CryptoPP::AutoSeededRandomPool _randomGenerator;  ///< Cryptographically secure random number generator
	CryptoPP::RSA::PublicKey       _publicKey;        ///< RSA public key for encryption operations
};

/**
 * @class       RSAPrivateWrapper
 * @brief       RSA private key wrapper for decryption and key generation
 * @details     Handles RSA private key operations including key generation,
 *              data decryption, and public key derivation. Uses OAEP padding
 *              with SHA-1 for secure operations.
 *              
 *              Features:
 *              - RSA key pair generation
 *              - Private key decryption with OAEP padding
 *              - Public key derivation from private key
 *              - Secure key serialization and deserialization
 *              - Comprehensive error handling
 *              
 * @note        This class is non-copyable and non-movable to prevent key duplication
 *              and ensure private key security.
 */
class RSAPrivateWrapper
{
public:
	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Default constructor - generates new RSA key pair
	 * @details     Automatically generates a cryptographically secure RSA-1024 key pair
	 *              using the system's random number generator.
	 *              Initializes all cryptographic components for secure operations.
	 */
	RSAPrivateWrapper();

	/**
	 * @brief       Constructor with existing private key
	 * @param[in]   privateKeyString    Serialized private key data
	 * @details     Loads an existing private key from serialized format.
	 *              Validates key format and initializes cryptographic components.
	 *              Throws exception for invalid key data.
	 */
	RSAPrivateWrapper(const std::string& privateKeyString);

	/**
	 * @brief       Virtual destructor for proper inheritance support
	 * @details     Ensures proper cleanup of cryptographic resources and
	 *              secure memory clearing of sensitive key data.
	 */
	virtual ~RSAPrivateWrapper() = default;

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Explicitly delete copy and move operations to prevent key duplication
	RSAPrivateWrapper(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper(RSAPrivateWrapper&& other) noexcept = delete;
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper& operator=(RSAPrivateWrapper&& other) noexcept = delete;

	// ================================
	// Key Management Methods
	// ================================

	/**
	 * @brief       Retrieves the private key in serialized format
	 * @return      Private key as serialized string
	 * @details     Returns the private key for external storage or transmission.
	 *              Uses secure serialization format for key preservation.
	 * @warning     Handle the returned private key with extreme security measures.
	 *              Store securely and never transmit over insecure channels.
	 */
	std::string getPrivateKey() const;

	/**
	 * @brief       Derives and retrieves the public key from the private key
	 * @return      Public key as serialized string
	 * @details     Extracts the public key component for sharing with other parties.
	 *              Uses protocol-compliant key format for interoperability.
	 *              Safe to share publicly as it cannot be used for decryption.
	 */
	std::string getPublicKey() const;

	// ================================
	// Cryptographic Operations
	// ================================

	/**
	 * @brief       Decrypts data using RSA private key with OAEP padding
	 * @param[in]   encryptedData    Pointer to encrypted data
	 * @param[in]   dataLength       Length of encrypted data in bytes
	 * @return      Decrypted plaintext as string
	 * @throws      CryptoPP::Exception if decryption fails
	 * @details     Uses RSAES-OAEP-SHA decryption scheme to recover original data.
	 *              Validates input parameters and handles decryption errors.
	 *              Suitable for decrypting data encrypted with corresponding public key.
	 */
	std::string decrypt(const uint8_t* encryptedData, size_t dataLength);

private:
	// ================================
	// Member Variables
	// ================================

	CryptoPP::AutoSeededRandomPool _randomGenerator;  ///< Cryptographically secure random number generator
	CryptoPP::RSA::PrivateKey      _privateKey;       ///< RSA private key for decryption operations
};
