/**
 * @author	Natanel Maor Fishman
 * @file	StringUtility.h
 * @brief       Comprehensive string manipulation utility class providing encoding,
 *              decoding, formatting, and time-based functionalities
 */
#pragma once
#include <string>
#include <cstdint>

 /**
  * @class StringUtility
  * @brief Static utility class for common string operations
  */
class StringUtility
{
public:
    // Conversion utilities
    static std::string hex(const uint8_t* buffer, const size_t size);        // Converts binary data to hex string
    static std::string unhex(const std::string& hexString);                  // Converts hex string to binary data

    // Encoding utilities
    static std::string encodeBase64(const std::string& input);               // Encodes string to Base64
    static std::string decodeBase64(const std::string& encodedString);       // Decodes Base64 string

    // String manipulation
    static void trim(std::string& stringToTrim);                             // Removes leading/trailing whitespace

    // Time utilities
    static std::string getTimestamp();                                       // Returns formatted current timestamp
};

