/**
 * @author	Natanel Maor Fishman
 * @file	RSAWrapper.h
 * @brief	Handle RSA encryption (asymmetric).
 */
#include "RSAWrapper.h"
#include "protocol.h"

 // Constructs a public key wrapper from a PublicKeyStruct
RSAPublicWrapper::RSAPublicWrapper(const PublicKeyStruct& publicKey)
{
	CryptoPP::StringSource ss((publicKey.publicKey), sizeof(publicKey.publicKey), true);
	_publicKey.Load(ss);
}

// Encrypts plain data using the public key
std::string RSAPublicWrapper::encrypt(const uint8_t* plain, size_t length)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(plain, length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

// Initializes a new RSA private key with specified bit size
RSAPrivateWrapper::RSAPrivateWrapper()
{
	_privateKey.Initialize(_rng, BITS);
}

// Constructs a private key wrapper from an existing key string
RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

// Returns the private key as a string
std::string RSAPrivateWrapper::getPrivateKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

// Returns the public key derived from the private key
std::string RSAPrivateWrapper::getPublicKey() const
{
	const CryptoPP::RSAFunction publicKey((_privateKey));
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

// Decrypts cipher data using the private key
std::string RSAPrivateWrapper::decrypt(const uint8_t* cipher, size_t length)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher((cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}
