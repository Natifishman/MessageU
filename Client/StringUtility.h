/**
 * @file        StringUtility.h
 * @author      Natanel Maor Fishman
 * @brief       String utility library providing encoding, decoding, and formatting capabilities
 * @details     Utility class for common string operations including binary-to-hex conversion,
 *              Base64 encoding/decoding, string trimming, and timestamp generation.
 *              Provides comprehensive string manipulation tools for data processing.
 * @version     2.0
 * @date        2025
 */

#pragma once

// ================================
// Standard Library Includes
// ================================

#include <string>
#include <cstdint>

// ================================
// Class Definition
// ================================

/**
 * @class       StringUtility
 * @brief       Static utility class for advanced string manipulation operations
 * @details     Provides a comprehensive set of string utilities for data encoding, decoding,
 *              formatting, and time-based operations. All methods are static and thread-safe.
 *              Includes robust error handling and input validation for production use.
 *              
 *              Features:
 *              - Binary to hexadecimal conversion
 *              - Base64 encoding and decoding
 *              - String trimming and formatting
 *              - Timestamp generation
 *              - Input validation and error handling
 *              - Thread-safe static methods
 *              
 * @note        This class cannot be instantiated - all methods are static.
 *              Designed for utility operations without object state.
 */
class StringUtility
{
public:
	// ================================
	// Copy Control (Deleted)
	// ================================

	// Prevent instantiation of utility class
	StringUtility() = delete;
	StringUtility(const StringUtility&) = delete;
	StringUtility& operator=(const StringUtility&) = delete;

	// ================================
	// Binary Data Conversion Methods
	// ================================

	/**
	 * @brief       Converts binary data to hexadecimal string representation
	 * @param[in]   binaryData    Pointer to binary data buffer
	 * @param[in]   dataSize      Size of binary data in bytes
	 * @return      Hexadecimal string representation of the binary data
	 * @details     Converts each byte to its two-character hex representation.
	 *              Returns empty string for null or empty input.
	 *              Uses efficient bit manipulation for conversion.
	 *              Suitable for cryptographic data and debugging output.
	 */
	static std::string hex(const uint8_t* binaryData, const size_t dataSize);

	/**
	 * @brief       Converts hexadecimal string to binary data
	 * @param[in]   hexString     Hexadecimal string to convert
	 * @return      Binary data as string
	 * @details     Converts pairs of hex characters back to binary bytes.
	 *              Returns empty string for invalid or empty input.
	 *              Validates hex string format and handles case-insensitive input.
	 *              Supports both uppercase and lowercase hex characters.
	 */
	static std::string unhex(const std::string& hexString);

	// ================================
	// Base64 Encoding Methods
	// ================================

	/**
	 * @brief       Encodes string data to Base64 format
	 * @param[in]   inputData     Input string to encode
	 * @return      Base64 encoded string
	 * @details     Uses CryptoPP's Base64 encoder for efficient and secure encoding.
	 *              Suitable for binary data and text encoding.
	 *              Handles padding and line breaks according to RFC 4648.
	 *              Returns empty string for null or empty input.
	 */
	static std::string encodeBase64(const std::string& inputData);

	/**
	 * @brief       Decodes Base64 string to original format
	 * @param[in]   encodedData   Base64 encoded string to decode
	 * @return      Decoded original data as string
	 * @details     Uses CryptoPP's Base64 decoder with comprehensive error handling.
	 *              Returns empty string for invalid Base64 input.
	 *              Handles padding variations and whitespace in input.
	 *              Validates Base64 character set and format.
	 */
	static std::string decodeBase64(const std::string& encodedData);

	// ================================
	// String Formatting Methods
	// ================================

	/**
	 * @brief       Removes leading and trailing whitespace from a string
	 * @param[in,out] targetString    String to trim (modified in-place)
	 * @details     Uses Boost's trim algorithm for efficient whitespace removal.
	 *              Modifies the input string directly for performance.
	 *              Handles various whitespace characters including tabs and newlines.
	 *              Preserves internal whitespace between words.
	 */
	static void trim(std::string& targetString);

	// ================================
	// Time and System Methods
	// ================================

	/**
	 * @brief       Generates current system timestamp in milliseconds
	 * @return      Current timestamp as string in milliseconds since epoch
	 * @details     Returns high-precision timestamp suitable for logging and
	 *              performance measurement applications.
	 *              Uses system clock for accurate time measurement.
	 *              Format: milliseconds since Unix epoch (January 1, 1970).
	 */
	static std::string getTimestamp();
};

