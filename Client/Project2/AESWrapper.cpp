/**
 * @author	Natanel Maor Fishman
 * @file	AESWrapper.cpp
 * @brief	Handle AES encryption (Symmetric) for enhanced security and flexibility.
 */
#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h> 
#include <string>
#include <cstring>


void AESWrapper::GenerateKey(uint8_t* const buffer, const size_t length)
{
	if (!buffer) {
		throw std::invalid_argument("Buffer cannot be null");
	}

	for (size_t i = 0; i < length; i += sizeof(unsigned int))
	{
		unsigned int temp;
		int result = _rdrand32_step(&temp);

		if (result == 0) {
			throw std::runtime_error("RDRAND failed to generate a random number");
		}

		// Copy the generated value to the buffer
		if (i + sizeof(unsigned int) <= length) {
			memcpy(&buffer[i], &temp, sizeof(unsigned int));
		}
		else {
			// Handle the last chunk if smaller than sizeof(unsigned int)
			memcpy(&buffer[i], &temp, length - i);
		}
	}
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key.symmetricKey, sizeof(_key.symmetricKey));
}


AESWrapper::AESWrapper(const SymmetricKeyStruct& symKey) : _key(symKey)
{
	// Validate key material if needed
}

//Encrypt a string using AES-CBC mode
std::string AESWrapper::encrypt(const std::string& plain) const
{
	if (plain.empty()) {
		return std::string();
	}

	return encrypt(reinterpret_cast<const uint8_t*>(plain.c_str()), plain.size());
}

//Encrypt raw data using AES-CBC mode
std::string AESWrapper::encrypt(const uint8_t* plain, size_t length) const
{
	// Validate input buffer
	if (!plain && length > 0) {
		throw std::invalid_argument("Invalid input buffer");
	}

	try {
		// TODO: Implement proper IV generation and handling (Didnt ask for it in the assignment)
		// WARNING for myself: In production code, IV should never be a fixed value.
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

		// Set up the encryption
		CryptoPP::AES::Encryption aesEncryption(_key.symmetricKey, sizeof(_key.symmetricKey));
		CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

		// Encrypt the data
		std::string cipher;
		CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
		stfEncryptor.Put(plain, length);
		stfEncryptor.MessageEnd();

		return cipher;
	}
	catch (const CryptoPP::Exception& e) {
		throw std::runtime_error(std::string("Encryption failed: ") + e.what());
	}
}


std::string AESWrapper::decrypt(const uint8_t* cipher, size_t length) const
{
	// Error handling
	if (!cipher && length > 0) {
		throw std::invalid_argument("Invalid input buffer");
	}

	try {
		// TODO: Implement proper IV handling
		// WARNING for myself: In production code, IV should match the one used for encryption
		CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

		// Set up the decryption
		CryptoPP::AES::Decryption aesDecryption(_key.symmetricKey, sizeof(_key.symmetricKey));
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

		// Decrypt the data
		std::string decrypted;
		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
		stfDecryptor.Put(cipher, length);
		stfDecryptor.MessageEnd();

		return decrypted;
	}
	catch (const CryptoPP::Exception& e) {
		throw std::runtime_error(std::string("Decryption failed: ") + e.what());
	}
}
