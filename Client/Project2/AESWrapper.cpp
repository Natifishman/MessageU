/**
 * @file        AESWrapper.cpp
 * @author      Natanel Maor Fishman
 * @brief       AES encryption wrapper providing symmetric encryption capabilities
 * @details     Implements AES-CBC mode encryption/decryption with secure key generation
 *              using RDRAND for cryptographic strength
 * @date        2025
 */

#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h> 
#include <string>
#include <cstring>

 /**
  * @brief       Generates cryptographically secure random bytes using hardware RDRAND
  * @param[out]  keyBuffer     Output buffer to store generated random bytes
  * @param[in]   bufferSize    Size of the buffer in bytes
  * @throws      std::invalid_argument if keyBuffer is null
  * @throws      std::runtime_error if RDRAND hardware instruction fails
  * @details     Uses Intel's RDRAND instruction for hardware-based entropy generation,
  *              ensuring cryptographic quality randomness for key material
  */
void AESWrapper::GenerateKey(uint8_t* const keyBuffer, const size_t bufferSize)
{
	if (!keyBuffer) {
		throw std::invalid_argument("Key buffer cannot be null");
	}

	for (size_t byteIndex = 0; byteIndex < bufferSize; byteIndex += sizeof(unsigned int))
	{
		unsigned int randomValue;
		int rdrandResult = _rdrand32_step(&randomValue);

		if (rdrandResult == 0) {
			throw std::runtime_error("Hardware RDRAND instruction failed to generate random number");
		}

		// Copy random bytes to the buffer, handling partial word at the end
		const size_t remainingBytes = bufferSize - byteIndex;
		const size_t bytesToCopy = (remainingBytes >= sizeof(unsigned int)) ?
			sizeof(unsigned int) : remainingBytes;

		memcpy(&keyBuffer[byteIndex], &randomValue, bytesToCopy);
	}
}

/**
 * @brief       Default constructor - generates a new random AES key
 * @details     Automatically generates a cryptographically secure 256-bit AES key
 *              using hardware random number generation
 */
AESWrapper::AESWrapper()
{
	GenerateKey(_aesKey.symmetricKey, sizeof(_aesKey.symmetricKey));
}

/**
 * @brief       Constructor with pre-existing symmetric key
 * @param[in]   existingKey   Pre-generated symmetric key structure
 * @details     Allows initialization with an existing key, useful for key sharing
 *              or persistent key storage scenarios
 */
AESWrapper::AESWrapper(const SymmetricKeyStruct& existingKey) : _aesKey(existingKey)
{
	// TODO: Add key validation logic here for production use
	// Validate key material integrity and strength
}

/**
 * @brief       Encrypts a string using AES-CBC mode
 * @param[in]   plaintextString    Input string to encrypt
 * @return      Encrypted data as binary string
 * @throws      std::runtime_error if encryption fails
 * @details     Convenience method for string encryption. Returns empty string
 *              if input is empty to avoid unnecessary processing
 */
std::string AESWrapper::encrypt(const std::string& plaintextString) const
{
	if (plaintextString.empty()) {
		return std::string();
	}

	return encrypt(reinterpret_cast<const uint8_t*>(plaintextString.c_str()),
		plaintextString.size());
}

/**
 * @brief       Encrypts raw binary data using AES-CBC mode
 * @param[in]   plaintextData      Pointer to input data buffer
 * @param[in]   dataLength         Length of input data in bytes
 * @return      Encrypted data as binary string
 * @throws      std::invalid_argument if input buffer is invalid
 * @throws      std::runtime_error if encryption operation fails
 * @details     Core encryption method using AES-256 in CBC mode with PKCS7 padding.
 *              Currently uses a fixed IV (zero-filled) for demonstration.
 *              Production code must use cryptographically secure random IVs.
 */
std::string AESWrapper::encrypt(const uint8_t* plaintextData, size_t dataLength) const
{
	// Validate input parameters
	if (!plaintextData && dataLength > 0) {
		throw std::invalid_argument("Plaintext data buffer cannot be null when data length > 0");
	}

	try {
		// CRITICAL SECURITY WARNING: Fixed IV is used for demonstration only
		// In production environments, generate a cryptographically secure random IV
		// for each encryption operation and transmit it alongside the ciphertext
		CryptoPP::byte initializationVector[CryptoPP::AES::BLOCKSIZE] = { 0 };

		// Initialize AES encryption engine with 256-bit key
		CryptoPP::AES::Encryption aesEncryptionEngine(_aesKey.symmetricKey,
			sizeof(_aesKey.symmetricKey));

		// Configure CBC mode encryption with the AES engine and IV
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryptionEngine(
			aesEncryptionEngine, initializationVector);

		// Perform the encryption with automatic PKCS7 padding
		std::string encryptedData;
		CryptoPP::StreamTransformationFilter encryptionFilter(
			cbcEncryptionEngine, new CryptoPP::StringSink(encryptedData));

		encryptionFilter.Put(plaintextData, dataLength);
		encryptionFilter.MessageEnd();

		return encryptedData;
	}
	catch (const CryptoPP::Exception& cryptoException) {
		throw std::runtime_error(std::string("AES encryption failed: ") +
			cryptoException.what());
	}
}

/**
 * @brief       Decrypts raw binary data using AES-CBC mode
 * @param[in]   encryptedData      Pointer to encrypted data buffer
 * @param[in]   dataLength         Length of encrypted data in bytes
 * @return      Decrypted plaintext as string
 * @throws      std::invalid_argument if input buffer is invalid
 * @throws      std::runtime_error if decryption operation fails
 * @details     Core decryption method using AES-256 in CBC mode with PKCS7 unpadding.
 *              The IV must match the one used during encryption. Currently uses
 *              the same fixed IV as the encryption method.
 */
std::string AESWrapper::decrypt(const uint8_t* encryptedData, size_t dataLength) const
{
	// Validate input parameters
	if (!encryptedData && dataLength > 0) {
		throw std::invalid_argument("Encrypted data buffer cannot be null when data length > 0");
	}

	try {
		// IV must match the one used during encryption
		// This should be extracted from the encrypted data or
		// transmitted separately in a secure manner
		CryptoPP::byte initializationVector[CryptoPP::AES::BLOCKSIZE] = { 0 };

		// Initialize AES decryption engine with 256-bit key
		CryptoPP::AES::Decryption aesDecryptionEngine(_aesKey.symmetricKey,
			sizeof(_aesKey.symmetricKey));

		// Configure CBC mode decryption with the AES engine and IV
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryptionEngine(
			aesDecryptionEngine, initializationVector);

		// Perform the decryption with automatic PKCS7 unpadding
		std::string decryptedPlaintext;
		CryptoPP::StreamTransformationFilter decryptionFilter(
			cbcDecryptionEngine, new CryptoPP::StringSink(decryptedPlaintext));

		decryptionFilter.Put(encryptedData, dataLength);
		decryptionFilter.MessageEnd();

		return decryptedPlaintext;
	}
	catch (const CryptoPP::Exception& cryptoException) {
		throw std::runtime_error(std::string("AES decryption failed: ") +
			cryptoException.what());
	}
}
