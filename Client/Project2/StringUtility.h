/**
 * @file        StringUtility.h
 * @author      Natanel Maor Fishman
 * @brief       string utility library providing encoding, decoding, and formatting capabilities
 * @details     utility class for common string operations including binary-to-hex conversion,
 *              Base64 encoding/decoding, string trimming, and timestamp generation
 * @date        2025
 */

#pragma once
#include <string>
#include <cstdint>

 /**
  * @class       StringUtility
  * @brief       Static utility class for advanced string manipulation operations
  * @details     Provides a comprehensive set of string utilities for data encoding, decoding,
  *              formatting, and time-based operations. All methods are static and thread-safe.
  *              Includes robust error handling and input validation for production use.
  */
class StringUtility
{
public:
    /**
     * @brief       Converts binary data to hexadecimal string representation
     * @param[in]   binaryData    Pointer to binary data buffer
     * @param[in]   dataSize      Size of binary data in bytes
     * @return      Hexadecimal string representation of the binary data
     * @details     Converts each byte to its two-character hex representation.
     *              Returns empty string for null or empty input.
     */
    static std::string hex(const uint8_t* binaryData, const size_t dataSize);

    /**
     * @brief       Converts hexadecimal string to binary data
     * @param[in]   hexString     Hexadecimal string to convert
     * @return      Binary data as string
     * @details     Converts pairs of hex characters back to binary bytes.
     *              Returns empty string for invalid or empty input.
     */
    static std::string unhex(const std::string& hexString);

    /**
     * @brief       Encodes string data to Base64 format
     * @param[in]   inputData     Input string to encode
     * @return      Base64 encoded string
     * @details     Uses CryptoPP's Base64 encoder for efficient and secure encoding.
     *              Suitable for binary data and text encoding.
     */
    static std::string encodeBase64(const std::string& inputData);

    /**
     * @brief       Decodes Base64 string to original format
     * @param[in]   encodedData   Base64 encoded string to decode
     * @return      Decoded original data as string
     * @details     Uses CryptoPP's Base64 decoder with comprehensive error handling.
     *              Returns empty string for invalid Base64 input.
     */
    static std::string decodeBase64(const std::string& encodedData);

    /**
     * @brief       Removes leading and trailing whitespace from a string
     * @param[in,out] targetString    String to trim (modified in-place)
     * @details     Uses Boost's trim algorithm for efficient whitespace removal.
     *              Modifies the input string directly for performance.
     */
    static void trim(std::string& targetString);

    /**
     * @brief       Generates current system timestamp in milliseconds
     * @return      Current timestamp as string in milliseconds since epoch
     * @details     Returns high-precision timestamp suitable for logging and
     *              performance measurement applications.
     */
    static std::string getTimestamp();

private:
    // Prevent instantiation of utility class
    StringUtility() = delete;
    StringUtility(const StringUtility&) = delete;
    StringUtility& operator=(const StringUtility&) = delete;
};

