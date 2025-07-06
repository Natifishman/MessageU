/**
 * @file        RSAWrapper.h
 * @author      Natanel Maor Fishman
 * @brief       RSA asymmetric encryption wrapper providing public/private key cryptography
 * @details     Implements RSA-1024 encryption/decryption using OAEP padding with SHA-1
 *              for secure key exchange and digital signatures
 * @date        2025
 * @warning     RSA-1024 is used for demonstration. Production environments should use
 *              RSA-2048 or higher for adequate security levels.
 */

#pragma once
#include <rsa.h>
#include <osrng.h>
#include <string>
#include "protocol.h"

 /// RSA key size in bits for cryptographic operations
static constexpr size_t RSA_KEY_SIZE_BITS = 1024;

/**
 * @class       RSAPublicWrapper
 * @brief       RSA public key wrapper for encryption operations
 * @details     Handles RSA public key operations including data encryption.
 *              Uses OAEP padding with SHA-1 for secure encryption.
 *              This class is non-copyable and non-movable to prevent key duplication.
 */
class RSAPublicWrapper
{
public:
	/// Size of public key in bytes, matching protocol specification
	static constexpr size_t PUBLIC_KEY_SIZE_BYTES = PUBLIC_KEY_LENGTH;

	/**
	 * @brief       Constructor with existing public key
	 * @param[in]   publicKeyData    Pre-generated public key structure
	 * @details     Loads an existing public key for encryption operations
	 */
	RSAPublicWrapper(const PublicKeyStruct& publicKeyData);

	/**
	 * @brief       Virtual destructor for proper inheritance support
	 */
	virtual ~RSAPublicWrapper() = default;

	/**
	 * @brief       Encrypts data using RSA public key with OAEP padding
	 * @param[in]   plaintextData    Pointer to data to encrypt
	 * @param[in]   dataLength       Length of data in bytes
	 * @return      Encrypted data as binary string
	 * @throws      CryptoPP::Exception if encryption fails
	 * @details     Uses RSAES-OAEP-SHA encryption scheme for secure data protection
	 */
	std::string encrypt(const uint8_t* plaintextData, size_t dataLength);

	// Explicitly delete copy and move operations to prevent key duplication
	RSAPublicWrapper(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper(RSAPublicWrapper&& other) noexcept = delete;
	RSAPublicWrapper& operator=(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper& operator=(RSAPublicWrapper&& other) noexcept = delete;

private:
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
 * @note        This class is non-copyable and non-movable to prevent key duplication
 *              and ensure private key security.
 */
class RSAPrivateWrapper
{
public:
	/**
	 * @brief       Default constructor - generates new RSA key pair
	 * @details     Automatically generates a cryptographically secure RSA-1024 key pair
	 *              using the system's random number generator
	 */
	RSAPrivateWrapper();

	/**
	 * @brief       Constructor with existing private key
	 * @param[in]   privateKeyString    Serialized private key data
	 * @details     Loads an existing private key from serialized format
	 */
	RSAPrivateWrapper(const std::string& privateKeyString);

	/**
	 * @brief       Virtual destructor for proper inheritance support
	 */
	virtual ~RSAPrivateWrapper() = default;

	/**
	 * @brief       Retrieves the private key in serialized format
	 * @return      Private key as serialized string
	 * @details     Returns the private key for external storage or transmission
	 * @warning     Handle the returned private key with extreme security measures
	 */
	std::string getPrivateKey() const;

	/**
	 * @brief       Derives and retrieves the public key from the private key
	 * @return      Public key as serialized string
	 * @details     Extracts the public key component for sharing with other parties
	 */
	std::string getPublicKey() const;

	/**
	 * @brief       Decrypts data using RSA private key with OAEP padding
	 * @param[in]   encryptedData    Pointer to encrypted data
	 * @param[in]   dataLength       Length of encrypted data in bytes
	 * @return      Decrypted plaintext as string
	 * @throws      CryptoPP::Exception if decryption fails
	 * @details     Uses RSAES-OAEP-SHA decryption scheme to recover original data
	 */
	std::string decrypt(const uint8_t* encryptedData, size_t dataLength);

	// Explicitly delete copy and move operations to prevent key duplication
	RSAPrivateWrapper(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper(RSAPrivateWrapper&& other) noexcept = delete;
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper& operator=(RSAPrivateWrapper&& other) noexcept = delete;

private:
	CryptoPP::AutoSeededRandomPool _randomGenerator;  ///< Cryptographically secure random number generator
	CryptoPP::RSA::PrivateKey      _privateKey;       ///< RSA private key for decryption operations
};
