/**
 * @file        ConfigManager.h
 * @author      Natanel Maor Fishman
 * @brief       Advanced file system management utility for configuration and data persistence
 * @details     Comprehensive file I/O manager providing secure file operations, directory management,
 *              and data persistence capabilities with robust error handling and resource management.
 *              Supports both binary and text file operations with automatic resource cleanup.
 * @version     2.0
 * @date        2025
 */

#pragma once

// ================================
// Standard Library Includes
// ================================

#include <cstdint>
#include <string>
#include <fstream>

// ================================
// Class Definition
// ================================

/**
 * @class       ConfigManager
 * @brief       Advanced file system management utility for secure file operations
 * @details     Provides comprehensive file I/O capabilities including binary and text operations,
 *              directory creation, file size management, and temporary directory access.
 *              Features automatic resource cleanup and robust error handling for production use.
 *              
 *              Features:
 *              - Binary and text file operations
 *              - Automatic directory creation
 *              - File size management and validation
 *              - Temporary directory access
 *              - Comprehensive error handling
 *              - Resource management and cleanup
 *              
 * @note        This class is non-copyable and non-movable to prevent resource conflicts
 *              and ensure proper file handle management.
 */
class ConfigManager
{
public:
	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Default constructor - initializes file manager
	 * @details     Creates a new file manager instance with no open files.
	 *              Initializes internal state for safe file operations.
	 */
	ConfigManager();

	/**
	 * @brief       Virtual destructor with automatic resource cleanup
	 * @details     Ensures proper cleanup of file handles and memory resources.
	 *              Closes any open files and releases associated system resources.
	 */
	virtual ~ConfigManager();

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Explicitly delete copy and move operations to prevent resource conflicts
	ConfigManager(const ConfigManager&) = delete;
	ConfigManager& operator=(const ConfigManager&) = delete;
	ConfigManager(ConfigManager&&) noexcept = delete;
	ConfigManager& operator=(ConfigManager&&) noexcept = delete;

	// ================================
	// File Management Methods
	// ================================

	/**
	 * @brief       Opens a file for reading or writing operations
	 * @param[in]   filePath    Path to the file to open
	 * @param[in]   writeMode   If true, opens for writing; if false, opens for reading
	 * @return      true if file opened successfully, false otherwise
	 * @details     Automatically creates parent directories if they don't exist.
	 *              Closes any previously open file before opening the new one.
	 *              Validates file path and handles permission errors.
	 */
	bool openFile(const std::string& filePath, bool writeMode = false);

	/**
	 * @brief       Safely closes the currently open file
	 * @details     Closes the file stream and releases associated resources.
	 *              Safe to call multiple times or when no file is open.
	 *              Ensures data is flushed to disk before closing.
	 */
	void closeFile();

	/**
	 * @brief       Deletes a file from the filesystem
	 * @param[in]   filePath    Path to the file to delete
	 * @return      true if file deleted successfully, false otherwise
	 * @details     Uses standard C++ file removal with comprehensive error handling.
	 *              Validates file existence and permissions before deletion.
	 */
	bool deleteFile(const std::string& filePath) const;

	/**
	 * @brief       Retrieves the size of the currently open file
	 * @return      File size in bytes, or 0 if file is not open or invalid
	 * @details     Preserves the current file position after size calculation.
	 *              Limited to 4GB files for memory safety.
	 *              Returns 0 for empty files or error conditions.
	 */
	size_t getFileSize() const;

	// ================================
	// Binary Data Operations
	// ================================

	/**
	 * @brief       Writes binary data to the currently open file
	 * @param[in]   sourceData      Pointer to data to write
	 * @param[in]   dataSize        Number of bytes to write
	 * @return      true if write operation successful, false otherwise
	 * @details     Performs comprehensive input validation and error handling.
	 *              Validates file is open for writing and data pointers.
	 *              Handles partial writes and disk space errors.
	 */
	bool writeBytes(const uint8_t* sourceData, size_t dataSize) const;

	/**
	 * @brief       Reads binary data from the currently open file
	 * @param[out]  destinationBuffer   Buffer to store read data
	 * @param[in]   dataSize            Number of bytes to read
	 * @return      true if read operation successful, false otherwise
	 * @details     Performs comprehensive input validation and error handling.
	 *              Validates file is open for reading and buffer pointers.
	 *              Handles end-of-file conditions and partial reads.
	 */
	bool readBytes(uint8_t* destinationBuffer, size_t dataSize) const;

	// ================================
	// Text Data Operations
	// ================================

	/**
	 * @brief       Writes a text line to the currently open file
	 * @param[in]   lineContent     Text line to write (newline automatically added)
	 * @return      true if write operation successful, false otherwise
	 * @details     Automatically appends a newline character to the line.
	 *              Validates file is open for writing and line content.
	 *              Handles encoding issues and disk space errors.
	 */
	bool writeTextLine(const std::string& lineContent) const;

	/**
	 * @brief       Reads a text line from the currently open file
	 * @param[out]  lineContent     Buffer to store the read line
	 * @return      true if read operation successful, false otherwise
	 * @details     Reads until newline character and removes it from the result.
	 *              Validates file is open for reading and buffer.
	 *              Handles end-of-file conditions and encoding issues.
	 */
	bool readTextLine(std::string& lineContent) const;

	// ================================
	// Complete File Operations
	// ================================

	/**
	 * @brief       Reads an entire file into memory in a single operation
	 * @param[in]   filePath        Path to the file to read
	 * @param[out]  fileData        Pointer to allocated memory containing file data
	 * @param[out]  fileSize        Size of the file in bytes
	 * @return      true if read operation successful, false otherwise
	 * @details     Allocates memory for the file data. Caller is responsible for
	 *              freeing the memory using delete[] when no longer needed.
	 *              Validates file existence and size limits before allocation.
	 *              Handles memory allocation failures gracefully.
	 */
	bool readFileComplete(const std::string& filePath, uint8_t*& fileData, size_t& fileSize);

	/**
	 * @brief       Writes data to a file in a single operation
	 * @param[in]   filePath        Path to the file to write
	 * @param[in]   fileContent     Content to write to the file
	 * @return      true if write operation successful, false otherwise
	 * @details     Creates the file if it doesn't exist and overwrites if it does.
	 *              Automatically creates parent directories if needed.
	 *              Validates content and handles disk space errors.
	 */
	bool writeFileComplete(const std::string& filePath, const std::string& fileContent);

	// ================================
	// System Information Methods
	// ================================

	/**
	 * @brief       Retrieves the system's temporary directory path
	 * @return      Absolute path to the system temporary directory
	 * @details     Uses Boost filesystem for cross-platform compatibility.
	 *              Falls back to "/tmp" on error.
	 *              Validates directory exists and is writable.
	 */
	std::string getTemporaryDirectory() const;

private:
	// ================================
	// Member Variables
	// ================================

	std::fstream* _fileStream;  ///< File stream for I/O operations
	bool          _isFileOpen;  ///< Indicates if a file is currently open
};
