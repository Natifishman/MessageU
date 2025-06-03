/**
 * @author		Natanel Maor Fishman
 * @file		RSAWrapper.h
 * @brief		Handles RSA asymmetric encryption and decryption operations
 * @details     Provides RSAPrivateWrapper and RSAPublicWrapper classes for
 *              secure RSA cryptographic operations
 */

#pragma once
#include <rsa.h>
#include <osrng.h>
#include <string>
#include "protocol.h"


static constexpr size_t BITS = 1024; //RSA key size in bits

class RSAPublicWrapper
{

public:
	static constexpr size_t KEYSIZE = PUBLIC_KEY_LENGTH; //Size of public key in bytes

private:
	CryptoPP::AutoSeededRandomPool _rng;		///< Random number generator
	CryptoPP::RSA::PublicKey       _publicKey;	///< RSA public key

public:
	RSAPublicWrapper(const PublicKeyStruct& publicKey);
	virtual ~RSAPublicWrapper() = default; //Default destructor

	// Deleted copy/move constructors and assignment operators
	RSAPublicWrapper(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper(RSAPublicWrapper&& other) noexcept = delete;
	RSAPublicWrapper& operator=(const RSAPublicWrapper& other) = delete;
	RSAPublicWrapper& operator=(RSAPublicWrapper&& other) noexcept = delete;

	// Encrypts data using the public key
	std::string encrypt(const uint8_t* plain, size_t length);
};


class RSAPrivateWrapper
{

private:
	CryptoPP::AutoSeededRandomPool _rng;		///< Random number generator
	CryptoPP::RSA::PrivateKey      _privateKey;	///< RSA private key


public:
	RSAPrivateWrapper();
	RSAPrivateWrapper(const std::string& key);	//Constructor with key
	virtual ~RSAPrivateWrapper() = default;		//Default destructor

	// Deleted copy/move constructors and assignment operators
	RSAPrivateWrapper(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper(RSAPrivateWrapper&& other) noexcept = delete;
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& other) = delete;
	RSAPrivateWrapper& operator=(RSAPrivateWrapper&& other) noexcept = delete;

	std::string getPrivateKey() const;
	std::string getPublicKey() const;

	/**
	 * @brief Decrypts data using the private key
	 * @param cipher Pointer to encrypted data
	 * @param length Length of encrypted data in bytes
	 */
	std::string decrypt(const uint8_t* cipher, size_t length);
};
