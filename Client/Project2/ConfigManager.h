/**
 * @author  Natanel Maor Fishman
 * @file    ConfigManager.h
 * @brief   Manages file system operations for configuration data.
 */

#pragma once

#include <cstdint>
#include <string>
#include <fstream>

class ConfigManager
{
public:
	// Constructor & Destructor
	ConfigManager();
	virtual ~ConfigManager();

	// Delete copy and move operations
	ConfigManager(const ConfigManager&) = delete;
	ConfigManager& operator=(const ConfigManager&) = delete;
	ConfigManager(ConfigManager&&) noexcept = delete;
	ConfigManager& operator=(ConfigManager&&) noexcept = delete;

	// File operations
	bool openFile(const std::string& filepath, bool write = false);
	void closeFile();
	bool deleteFile(const std::string& filepath) const;
	size_t getFileSize() const;

	// Data handling
	bool writeBytes(const uint8_t* src, size_t bytes) const;
	bool readBytes(uint8_t* dest, size_t bytes) const;
	bool writeTextLine(const std::string& line) const;
	bool readTextLine(std::string& line) const;

	// Batch file operations
	bool readFileComplete(const std::string& filepath, uint8_t*& file, size_t& bytes);
	bool writeFileComplete(const std::string& filepath, const std::string& data);

	// Utility
	std::string getTemporaryDirectory() const;

private:
	std::fstream* m_fileStream; // File stream for I/O operations
	bool m_isOpen;              // Indicates if a file is currently open
};
