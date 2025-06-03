/**
 * @author	Natanel Maor Fishman
 * @file	StringUtility.cpp
 * @brief	Implementation of string manipulation utility functions
 */
#include "StringUtility.h"
#include <base64.h>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>

 // Encodes input string to Base64 format
std::string StringUtility::encodeBase64(const std::string& input)
{
	std::string encoded;
	CryptoPP::StringSource ss(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));
	return encoded;
}


// Decodes Base64 string to original format with error handling
std::string StringUtility::decodeBase64(const std::string& encodedString)
{
	std::string decoded;
	try {
		CryptoPP::StringSource source(encodedString, true,
			new CryptoPP::Base64Decoder(
				new CryptoPP::StringSink(decoded)
			)
		);
	}
	catch (...) {
		return "";
	}
	return decoded;
}


// Converts byte buffer to hexadecimal string representation
std::string StringUtility::hex(const uint8_t* buffer, const size_t size)
{
	if (buffer == nullptr || size == 0) {
		return "";
	}

	const std::string byteString(buffer, buffer + size);
	if (byteString.empty())
		return "";

	try
	{
		return boost::algorithm::hex(byteString);
	}
	catch (...)
	{
		return "";
	}
}


// Converts hexadecimal string to binary representation
std::string StringUtility::unhex(const std::string& hexString)
{
	// Input validation
	if (hexString.empty()) {
		return "";
	}

	try
	{
		return boost::algorithm::unhex(hexString);
	}
	catch (...)
	{
		return "";
	}
}

// Removes leading and trailing whitespace from a string
void StringUtility::trim(std::string& stringToTrim)
{
	boost::algorithm::trim(stringToTrim);
}

// Returns current system timestamp in milliseconds as a string
std::string StringUtility::getTimestamp()
{
	const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch());
	return std::to_string(now.count());
}