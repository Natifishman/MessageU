/**
 * @author	Natanel Maor Fishman
 * @file	AESWrapper.h
 * @brief       Secure symmetric encryption implementation using the AES algorithm
 * @details     Provides functionality for key generation, data encryption and decryption
 */

#pragma once
#include <string>
#include "protocol.h"

class AESWrapper
{
public:
	// Generates a cryptographically secure random key of specified length
	static void GenerateKey(uint8_t* const buffer, const size_t length);

	// Constructors
	AESWrapper();
	AESWrapper(const SymmetricKeyStruct& symKey);
	virtual ~AESWrapper() = default; // Default virtual destructor

	// Encryption/decryption functions
	std::string encrypt(const std::string& plain) const;
	std::string encrypt(const uint8_t* plain, size_t length) const;
	std::string decrypt(const uint8_t* cipher, size_t length) const;

	// Delete copy and move operations to prevent unintended key duplication
	AESWrapper(const AESWrapper& other) = delete;
	AESWrapper(AESWrapper&& other) noexcept = delete;
	AESWrapper& operator=(const AESWrapper& other) = delete;
	AESWrapper& operator=(AESWrapper&& other) noexcept = delete;

	// Retrieves the current encryption key
	SymmetricKeyStruct getKey() const { return _key; }

private:
	SymmetricKeyStruct _key; // Stores the encryption/decryption key
};