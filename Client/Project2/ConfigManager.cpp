/**
 * @author  Natanel Maor Fishman
 * @file    ConfigManager.cpp
 * @brief   Handle files (on file system).
 */

#include "ConfigManager.h"

#include <algorithm>
#include <fstream>
#include <boost/filesystem.hpp>

// Default constructor
ConfigManager::ConfigManager() : m_fileStream(nullptr), m_isOpen(false)
{
}

// Default destructor
ConfigManager::~ConfigManager()
{
	closeFile();
}


/**
 * Opens a file for reading or writing operations
 * Creates necessary directory structure if it doesn't exist
 */
bool ConfigManager::openFile(const std::string& filePath, bool write)
{
	// handle empty file path
	if (filePath.empty()) {
		return false;
	}

	try
	{
		// Clean up any existing file stream before creating a new one
		closeFile();

		const auto openMode = write ? (std::fstream::binary | std::fstream::out) : (std::fstream::binary | std::fstream::in);
		m_fileStream = new std::fstream;

		// Create parent directories if needed
		const auto parentDir = boost::filesystem::path(filePath).parent_path();
		if (!parentDir.empty())
		{
			(void)create_directories(parentDir);
		}

		m_fileStream->open(filePath, openMode);
		m_isOpen = m_fileStream->is_open();

		return m_isOpen;
	}
	catch (...) {
		// Log error here if needed
		m_isOpen = false;
		return false;
	}
}


// Safely closes the current file stream
void ConfigManager::closeFile()
{
	try
	{
		if (m_fileStream != nullptr) {
			m_fileStream->close();
		}
	}
	catch (...) {
		// Log error not needed
	}

	// Clean up resources
	delete m_fileStream;
	m_fileStream = nullptr;
	m_isOpen = false;
}

// Read a specified number of bytes from the file stream
bool ConfigManager::readBytes(uint8_t* const destination, const size_t byteCount) const
{
	// handle invalid arguments
	if (!m_fileStream || !m_isOpen || !destination || byteCount == 0) {
		return false;
	}

	try
	{
		m_fileStream->read(reinterpret_cast<char*>(destination), byteCount);
		return true;
	}
	catch (...) {
		// Log error here if needed
		return false;
	}
}


// Writes a specified number of bytes to the file stream
bool ConfigManager::writeBytes(const uint8_t* const source, const size_t byteCount) const
{
	// handle invalid arguments
	if (!m_fileStream || !m_isOpen || !source || byteCount == 0) {
		return false;
	}

	try
	{
		m_fileStream->write(reinterpret_cast<const char*>(source), byteCount);
		return true;
	}
	catch (...) {
		// Log error here if needed
		return false;
	}
}


// Deletes a file from the filesystem
bool ConfigManager::deleteFile(const std::string& filePath) const
{
	try
	{
		// handle empty file path
		return (0 == std::remove(filePath.c_str()));
	}
	catch (...)
	{
		return false;
	}
}


/**
 * Read a single line from fs to line.
 */
bool ConfigManager::readTextLine(std::string& lineContent) const
{
	// handle invalid arguments
	if (!m_fileStream || !m_isOpen) {
		return false;
	}

	try {
		if (!std::getline(*m_fileStream, lineContent)) {
			return false;
		}
		return !lineContent.empty();
	}
	catch (...)
	{
		// Log error here if needed
		return false;
	}
}

// Writes a string to the file and appends a newline character
bool ConfigManager::writeTextLine(const std::string& lineContent) const
{
	std::string lineWithNewline = lineContent + "\n";
	return writeBytes(reinterpret_cast<const uint8_t*>(lineWithNewline.c_str()), lineWithNewline.size());
}


// Calculates the size of the currently open file
size_t ConfigManager::getFileSize() const
{
	// handle invalid arguments
	if (!m_fileStream || !m_isOpen) {
		return 0;
	}

	try
	{
		// Save current position
		const auto currentPos = m_fileStream->tellg();

		// Get file size
		m_fileStream->seekg(0, std::fstream::end);
		const auto fileSize = m_fileStream->tellg();

		// Restore position
		m_fileStream->seekg(currentPos);

		// Validate size (up to 4GB).
		if ((fileSize <= 0) || (fileSize > UINT32_MAX)) {
			return 0;
		}

		return static_cast<size_t>(fileSize);
	}
	catch (...)
	{
		// Log error here if needed
		return 0;
	}
}

// Reads an entire file into memory in a single operation
bool ConfigManager::readFileComplete(const std::string& filePath, uint8_t*& fileData, size_t& fileSize)
{
	// handle empty file path
	if (!openFile(filePath)) {
		return false;
	}

	// Get file size
	fileSize = getFileSize();
	if (fileSize == 0) {
		closeFile();
		return false;
	}

	try {
		fileData = new uint8_t[fileSize];
		const bool success = readBytes(fileData, fileSize);

		// Clean up if read failed
		if (!success)
		{
			delete[] fileData;
			fileData = nullptr;
		}

		closeFile();
		return success;
	}
	catch (...) {
		closeFile();
		return false;
	}
}

// Open and write data to file.
bool ConfigManager::writeFileComplete(const std::string& filePath, const std::string& content)
{
	// handle empty file path
	if (content.empty() || !openFile(filePath, true)) {
		return false;
	}

	const bool success = writeBytes(reinterpret_cast<const uint8_t* const>(content.c_str()), content.size());
	
	closeFile();
	return success;
}

// Returns absolute path to %TMP% folder.
std::string ConfigManager::getTemporaryDirectory() const
{
	try {
		return boost::filesystem::temp_directory_path().string();
	}
	catch (...) {
		// Fallback to a default temp path if needed
		return "/tmp";
	}
}
