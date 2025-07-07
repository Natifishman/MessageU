/**
 * @file        StringUtility.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of string utility functions for encoding, decoding, and formatting.
 * @details     Provides static utility methods for string manipulation, encoding, and time operations.
 * @date        2025
 */

#include "StringUtility.h"
#include <base64.h>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>

 /**
  * @brief       Encodes string data to Base64 format
  * @param[in]   inputData     Input string to encode
  * @return      Base64 encoded string
  * @details     Uses CryptoPP's Base64 encoder for efficient and secure encoding.
  *              Suitable for binary data and text encoding with automatic padding.
  */
std::string StringUtility::encodeBase64(const std::string& inputData)
{
	std::string encodedResult;

	// Use CryptoPP's Base64 encoder with automatic padding
	CryptoPP::StringSource dataSource(inputData, true,
		new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedResult)));

	return encodedResult;
}

/**
 * @brief       Decodes Base64 string to original format with comprehensive error handling
 * @param[in]   encodedData   Base64 encoded string to decode
 * @return      Decoded original data as string
 * @details     Uses CryptoPP's Base64 decoder with robust error handling.
 *              Returns empty string for invalid Base64 input to prevent crashes.
 */
std::string StringUtility::decodeBase64(const std::string& encodedData)
{
	std::string decodedResult;

	try {
		// Attempt to decode the Base64 string with error handling
		CryptoPP::StringSource encodedSource(encodedData, true,
			new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedResult)));
	}
	catch (...) {
		// Return empty string for any decoding errors
		return "";
	}

	return decodedResult;
}

/**
 * @brief       Converts binary data to hexadecimal string representation
 * @param[in]   binaryData    Pointer to binary data buffer
 * @param[in]   dataSize      Size of binary data in bytes
 * @return      Hexadecimal string representation of the binary data
 * @details     Converts each byte to its two-character hex representation.
 *              Includes comprehensive input validation and error handling.
 */
std::string StringUtility::hex(const uint8_t* binaryData, const size_t dataSize)
{
	// Validate input parameters
	if (binaryData == nullptr || dataSize == 0) {
		return "";
	}

	// Convert binary data to string for Boost hex processing
	const std::string binaryString(binaryData, binaryData + dataSize);
	if (binaryString.empty()) {
		return "";
	}

	try {
		// Use Boost's hex algorithm for efficient conversion
		return boost::algorithm::hex(binaryString);
	}
	catch (...) {
		// Return empty string for any conversion errors
		return "";
	}
}

/**
 * @brief       Converts hexadecimal string to binary data
 * @param[in]   hexString     Hexadecimal string to convert
 * @return      Binary data as string
 * @details     Converts pairs of hex characters back to binary bytes.
 *              Includes input validation and comprehensive error handling.
 */
std::string StringUtility::unhex(const std::string& hexString)
{
	// Validate input string
	if (hexString.empty()) {
		return "";
	}

	try {
		// Use Boost's unhex algorithm for efficient conversion
		return boost::algorithm::unhex(hexString);
	}
	catch (...) {
		// Return empty string for any conversion errors
		return "";
	}
}

/**
 * @brief       Removes leading and trailing whitespace from a string
 * @param[in,out] targetString    String to trim (modified in-place)
 * @details     Uses Boost's trim algorithm for efficient whitespace removal.
 *              Modifies the input string directly for optimal performance.
 */
void StringUtility::trim(std::string& targetString)
{
	boost::algorithm::trim(targetString);
}

/**
 * @brief       Generates current system timestamp in milliseconds
 * @return      Current timestamp as string in milliseconds since epoch
 * @details     Returns high-precision timestamp suitable for logging,
 *              performance measurement, and time-based operations.
 */
std::string StringUtility::getTimestamp()
{
	// Get current time in milliseconds since epoch for high precision
	const auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch());

	return std::to_string(currentTime.count());
}