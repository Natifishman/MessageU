/**
 * @file        RSAWrapper.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of RSA asymmetric encryption wrapper.
 * @details     Provides all cryptographic operations for RSA key management, encryption, and decryption.
 * @date        2025
 */

#include "RSAWrapper.h"
#include "protocol.h"

// ================================
// RSAWrapper.cpp - Implementation
// ================================

/**
 * @brief       Constructor with existing public key
 * @param[in]   publicKeyData    Pre-generated public key structure
 * @details     Loads an existing public key from the provided structure
 *              for subsequent encryption operations
 */
RSAPublicWrapper::RSAPublicWrapper(const PublicKeyStruct& publicKeyData)
{
	// Load the public key from the provided key structure
	CryptoPP::StringSource keySource(publicKeyData.publicKey,
		sizeof(publicKeyData.publicKey),
		true);
	_publicKey.Load(keySource);
}

/**
 * @brief       Encrypts data using RSA public key with OAEP padding
 * @param[in]   plaintextData    Pointer to data to encrypt
 * @param[in]   dataLength       Length of data in bytes
 * @return      Encrypted data as binary string
 * @throws      CryptoPP::Exception if encryption fails
 * @details     Uses RSAES-OAEP-SHA encryption scheme for secure data protection.
 *              The encrypted data can only be decrypted with the corresponding private key.
 */
std::string RSAPublicWrapper::encrypt(const uint8_t* plaintextData, size_t dataLength)
{
	std::string encryptedData;

	// Create RSA encryption engine with OAEP padding and SHA-1
	CryptoPP::RSAES_OAEP_SHA_Encryptor encryptionEngine(_publicKey);

	// Perform the encryption with automatic padding
	CryptoPP::StringSource dataSource(plaintextData, dataLength, true,
		new CryptoPP::PK_EncryptorFilter(_randomGenerator, encryptionEngine,
			new CryptoPP::StringSink(encryptedData)));

	return encryptedData;
}

/**
 * @brief       Default constructor - generates new RSA key pair
 * @details     Automatically generates a cryptographically secure RSA-1024 key pair
 *              using the system's random number generator for secure operations
 */
RSAPrivateWrapper::RSAPrivateWrapper()
{
	// Generate a new RSA-1024 private key using cryptographically secure random numbers
	_privateKey.Initialize(_randomGenerator, RSA_KEY_SIZE_BITS);
}

/**
 * @brief       Constructor with existing private key
 * @param[in]   privateKeyString    Serialized private key data
 * @details     Loads an existing private key from serialized format for
 *              decryption operations or key management
 */
RSAPrivateWrapper::RSAPrivateWrapper(const std::string& privateKeyString)
{
	// Load the private key from the serialized string format
	CryptoPP::StringSource keySource(privateKeyString, true);
	_privateKey.Load(keySource);
}

/**
 * @brief       Retrieves the private key in serialized format
 * @return      Private key as serialized string
 * @details     Returns the private key for external storage or transmission.
 *              The key is serialized in CryptoPP's standard format.
 * @warning     Handle the returned private key with extreme security measures
 */
std::string RSAPrivateWrapper::getPrivateKey() const
{
	std::string serializedPrivateKey;
	CryptoPP::StringSink keySink(serializedPrivateKey);
	_privateKey.Save(keySink);
	return serializedPrivateKey;
}

/**
 * @brief       Derives and retrieves the public key from the private key
 * @return      Public key as serialized string
 * @details     Extracts the public key component from the private key for
 *              sharing with other parties. The public key can be used for
 *              encryption operations by other parties.
 */
std::string RSAPrivateWrapper::getPublicKey() const
{
	// Extract the public key component from the private key
	const CryptoPP::RSAFunction publicKeyComponent(_privateKey);

	std::string serializedPublicKey;
	CryptoPP::StringSink keySink(serializedPublicKey);
	publicKeyComponent.Save(keySink);

	return serializedPublicKey;
}

/**
 * @brief       Decrypts data using RSA private key with OAEP padding
 * @param[in]   encryptedData    Pointer to encrypted data
 * @param[in]   dataLength       Length of encrypted data in bytes
 * @return      Decrypted plaintext as string
 * @throws      CryptoPP::Exception if decryption fails
 * @details     Uses RSAES-OAEP-SHA decryption scheme to recover original data.
 *              This operation can only succeed if the data was encrypted with
 *              the corresponding public key.
 */
std::string RSAPrivateWrapper::decrypt(const uint8_t* encryptedData, size_t dataLength)
{
	std::string decryptedPlaintext;

	// Create RSA decryption engine with OAEP padding and SHA-1
	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptionEngine(_privateKey);

	// Perform the decryption with automatic unpadding
	CryptoPP::StringSource encryptedSource(encryptedData, dataLength, true,
		new CryptoPP::PK_DecryptorFilter(_randomGenerator, decryptionEngine,
			new CryptoPP::StringSink(decryptedPlaintext)));

	return decryptedPlaintext;
}
