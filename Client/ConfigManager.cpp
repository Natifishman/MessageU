/**
 * @file        ConfigManager.cpp
 * @author      Natanel Maor Fishman
 * @brief       Advanced file system management utility implementation
 * @details     Implementation of comprehensive file I/O operations with robust error handling,
 *              directory management, and resource cleanup for production environments
 * @date        2025
 */

#include "ConfigManager.h"

#include <algorithm>
#include <fstream>
#include <boost/filesystem.hpp>

 /**
  * @brief       Default constructor - initializes file manager
  * @details     Creates a new file manager instance with no open files
  */
ConfigManager::ConfigManager() : _fileStream(nullptr), _isFileOpen(false)
{
}

/**
 * @brief       Virtual destructor with automatic resource cleanup
 * @details     Ensures proper cleanup of file handles and memory resources
 */
ConfigManager::~ConfigManager()
{
	closeFile();
}

/**
 * @brief       Opens a file for reading or writing operations
 * @param[in]   filePath    Path to the file to open
 * @param[in]   writeMode   If true, opens for writing; if false, opens for reading
 * @return      true if file opened successfully, false otherwise
 * @details     Automatically creates parent directories if they don't exist.
 *              Closes any previously open file before opening the new one.
 *              Uses comprehensive error handling for robust operation.
 */
bool ConfigManager::openFile(const std::string& filePath, bool writeMode)
{
	// Validate input file path
	if (filePath.empty()) {
		return false;
	}

	try {
		// Clean up any existing file stream before creating a new one
		closeFile();

		// Determine appropriate file open mode
		const auto openMode = writeMode ?
			(std::fstream::binary | std::fstream::out) :
			(std::fstream::binary | std::fstream::in);

		_fileStream = new std::fstream;

		// Create parent directories if they don't exist
		const auto parentDirectory = boost::filesystem::path(filePath).parent_path();
		if (!parentDirectory.empty()) {
			(void)create_directories(parentDirectory);
		}

		// Open the file with specified mode
		_fileStream->open(filePath, openMode);
		_isFileOpen = _fileStream->is_open();

		return _isFileOpen;
	}
	catch (...) {
		// Comprehensive error handling - reset state on any exception
		_isFileOpen = false;
		return false;
	}
}

/**
 * @brief       Safely closes the currently open file
 * @details     Closes the file stream and releases associated resources.
 *              Safe to call multiple times or when no file is open.
 */
void ConfigManager::closeFile()
{
	try {
		if (_fileStream != nullptr) {
			_fileStream->close();
		}
	}
	catch (...) {
		// Silent error handling for close operations
	}

	// Clean up resources regardless of close success
	delete _fileStream;
	_fileStream = nullptr;
	_isFileOpen = false;
}

/**
 * @brief       Reads binary data from the currently open file
 * @param[out]  destinationBuffer   Buffer to store read data
 * @param[in]   dataSize            Number of bytes to read
 * @return      true if read operation successful, false otherwise
 * @details     Performs comprehensive input validation and error handling
 */
bool ConfigManager::readBytes(uint8_t* destinationBuffer, size_t dataSize) const
{
	// Validate input parameters and file state
	if (!_fileStream || !_isFileOpen || !destinationBuffer || dataSize == 0) {
		return false;
	}

	try {
		_fileStream->read(reinterpret_cast<char*>(destinationBuffer), dataSize);
		return true;
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Writes binary data to the currently open file
 * @param[in]   sourceData      Pointer to data to write
 * @param[in]   dataSize        Number of bytes to write
 * @return      true if write operation successful, false otherwise
 * @details     Performs comprehensive input validation and error handling
 */
bool ConfigManager::writeBytes(const uint8_t* sourceData, size_t dataSize) const
{
	// Validate input parameters and file state
	if (!_fileStream || !_isFileOpen || !sourceData || dataSize == 0) {
		return false;
	}

	try {
		_fileStream->write(reinterpret_cast<const char*>(sourceData), dataSize);
		return true;
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Deletes a file from the filesystem
 * @param[in]   filePath    Path to the file to delete
 * @return      true if file deleted successfully, false otherwise
 * @details     Uses standard C++ file removal with comprehensive error handling
 */
bool ConfigManager::deleteFile(const std::string& filePath) const
{
	try {
		// Use standard C++ file removal with error checking
		return (0 == std::remove(filePath.c_str()));
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Reads a text line from the currently open file
 * @param[out]  lineContent     Buffer to store the read line
 * @return      true if read operation successful, false otherwise
 * @details     Reads until newline character and removes it from the result.
 *              Returns false for empty lines to distinguish from EOF.
 */
bool ConfigManager::readTextLine(std::string& lineContent) const
{
	// Validate file state
	if (!_fileStream || !_isFileOpen) {
		return false;
	}

	try {
		if (!std::getline(*_fileStream, lineContent)) {
			return false;
		}
		return !lineContent.empty();
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Writes a text line to the currently open file
 * @param[in]   lineContent     Text line to write (newline automatically added)
 * @return      true if write operation successful, false otherwise
 * @details     Automatically appends a newline character to the line
 */
bool ConfigManager::writeTextLine(const std::string& lineContent) const
{
	std::string lineWithNewline = lineContent + "\n";
	return writeBytes(reinterpret_cast<const uint8_t*>(lineWithNewline.c_str()),
		lineWithNewline.size());
}

/**
 * @brief       Retrieves the size of the currently open file
 * @return      File size in bytes, or 0 if file is not open or invalid
 * @details     Preserves the current file position after size calculation.
 *              Limited to 4GB files for memory safety.
 */
size_t ConfigManager::getFileSize() const
{
	// Validate file state
	if (!_fileStream || !_isFileOpen) {
		return 0;
	}

	try {
		// Save current file position
		const auto currentPosition = _fileStream->tellg();

		// Seek to end to get file size
		_fileStream->seekg(0, std::fstream::end);
		const auto fileSize = _fileStream->tellg();

		// Restore original position
		_fileStream->seekg(currentPosition);

		// Validate file size (limited to 4GB for memory safety)
		if ((fileSize <= 0) || (fileSize > UINT32_MAX)) {
			return 0;
		}

		return static_cast<size_t>(fileSize);
	}
	catch (...) {
		return 0;
	}
}

/**
 * @brief       Reads an entire file into memory in a single operation
 * @param[in]   filePath        Path to the file to read
 * @param[out]  fileData        Pointer to allocated memory containing file data
 * @param[out]  fileSize        Size of the file in bytes
 * @return      true if read operation successful, false otherwise
 * @details     Allocates memory for the file data. Caller is responsible for
 *              freeing the memory using delete[] when no longer needed.
 */
bool ConfigManager::readFileComplete(const std::string& filePath, uint8_t*& fileData, size_t& fileSize)
{
	// Open the file for reading
	if (!openFile(filePath)) {
		return false;
	}

	// Get file size for memory allocation
	fileSize = getFileSize();
	if (fileSize == 0) {
		closeFile();
		return false;
	}

	try {
		// Allocate memory for file data
		fileData = new uint8_t[fileSize];
		const bool readSuccess = readBytes(fileData, fileSize);

		// Clean up allocated memory if read failed
		if (!readSuccess) {
			delete[] fileData;
			fileData = nullptr;
		}

		closeFile();
		return readSuccess;
	}
	catch (...) {
		closeFile();
		return false;
	}
}

/**
 * @brief       Writes data to a file in a single operation
 * @param[in]   filePath        Path to the file to write
 * @param[in]   fileContent     Content to write to the file
 * @return      true if write operation successful, false otherwise
 * @details     Creates the file if it doesn't exist and overwrites if it does
 */
bool ConfigManager::writeFileComplete(const std::string& filePath, const std::string& fileContent)
{
	// Validate input and open file for writing
	if (fileContent.empty() || !openFile(filePath, true)) {
		return false;
	}

	const bool writeSuccess = writeBytes(reinterpret_cast<const uint8_t* const>(fileContent.c_str()),
		fileContent.size());

	closeFile();
	return writeSuccess;
}

/**
 * @brief       Retrieves the system's temporary directory path
 * @return      Absolute path to the system temporary directory
 * @details     Uses Boost filesystem for cross-platform compatibility.
 *              Falls back to "/tmp" on error for Unix-like systems.
 */
std::string ConfigManager::getTemporaryDirectory() const
{
	try {
		return boost::filesystem::temp_directory_path().string();
	}
	catch (...) {
		// Fallback to default temporary directory on error
		return "/tmp";
	}
}
