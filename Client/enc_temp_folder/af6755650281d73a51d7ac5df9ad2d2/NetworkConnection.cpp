/**
 * @author	Natanel Maor Fishman
 * @file	NetworkConnection.cpp
 * @brief	Handle socket (Input/Output) for client-server communication.
 */

#include "NetworkConnection.h"
#include <boost/asio.hpp>
#include <stdexcept>
#include <algorithm>

using boost::asio::ip::tcp;
using boost::asio::io_context;

// ================================
// NetworkConnection.cpp - Implementation
// ================================
/**
 * @file        NetworkConnection.cpp
 * @author      Natanel Maor Fishman
 * @brief       Implementation of network connection management for client-server communication.
 * @details     Handles all socket operations, connection setup, teardown, and data transfer.
 *              Provides cross-platform networking using Boost ASIO, with robust error handling and resource management.
 * @date        2025
 */

// ================================
// Namespace Usage
// ================================

// ================================
// Constructor and Destructor
// ================================

/**
 * @brief       Default constructor - initializes network connection and detects system endianness
 * @details     Sets up internal state and determines system endianness for cross-platform compatibility.
 */
NetworkConnection::NetworkConnection() : m_ioContext(nullptr), m_resolver(nullptr), m_socket(nullptr), m_isConnected(false)
{
	// Detect system endianness using union approach
	union
	{
		uint32_t integer;
		uint8_t bytes[sizeof(uint32_t)];
	} endianCheck{ 1 };
	m_isBigEndian = (endianCheck.bytes[0] == 0);
}

/**
 * @brief       Destructor - ensures proper cleanup of all networking resources
 * @details     Calls disconnectSocket to release all allocated resources and close any open sockets.
 */
NetworkConnection::~NetworkConnection()
{
	disconnectSocket();
}

// ================================
// Public Interface Methods
// ================================

/**
 * @brief       Configures connection endpoint (address and port)
 * @param[in]   address   Remote endpoint IP address
 * @param[in]   port      Remote endpoint port number
 * @return      true if configuration successful, false otherwise
 * @details     Validates and stores endpoint configuration for future connection attempts. Does not establish connection.
 */
bool NetworkConnection::configureEndpoint(const std::string& address, const std::string& port)
{
	if (!validateAddress(address) || !validatePort(port)) {
		return false;
	}
	m_address = address;
	m_port = port;
	return true;
}

/**
 * @brief       Establishes connection to the configured endpoint
 * @return      true if connection successful, false otherwise
 * @details     Attempts to establish TCP connection to the configured address and port. Updates connection state accordingly.
 */
bool NetworkConnection::establishConnection()
{
	if (!validateAddress(m_address) || !validatePort(m_port)) {
		return false;
	}
	try
	{
		disconnectSocket(); // Ensure clean state before connecting
		m_ioContext = new io_context;
		m_resolver = new tcp::resolver(*m_ioContext);
		m_socket = new tcp::socket(*m_ioContext);
		auto endpoints = m_resolver->resolve(m_address, m_port);
		boost::asio::connect(*m_socket, endpoints);
		m_socket->set_option(tcp::no_delay(true));
		m_socket->non_blocking(false);
		m_isConnected = true;
		return true;
	}
	catch (...)
	{
		m_isConnected = false;
		return false;
	}
}

/**
 * @brief       Closes the active connection and releases all resources
 * @details     Gracefully closes the socket connection and updates connection state. Ensures proper resource cleanup.
 */
void NetworkConnection::disconnectSocket()
{
	try
	{
		if (m_socket != nullptr && m_socket->is_open()) {
			boost::system::error_code ec;
			m_socket->shutdown(tcp::socket::shutdown_both, ec);
			m_socket->close();
		}
	}
	catch (...) {} // Do Nothing

	if (m_socket != nullptr) {
		delete m_socket;
		m_socket = nullptr;
	}
	if (m_resolver != nullptr) {
		delete m_resolver;
		m_resolver = nullptr;
	}
	if (m_ioContext != nullptr) {
		delete m_ioContext;
		m_ioContext = nullptr;
	}
	m_isConnected = false;
}

/**
 * @brief       Checks if the connection is active
 * @return      true if connected, false otherwise
 * @details     Returns current connection state without performing network operations.
 */
bool NetworkConnection::isConnected() const
{
	return m_isConnected;
}

/**
 * @brief       Receives data from the socket
 * @param[out]  buffer    Buffer to store received data
 * @param[in]   size      Size of data to receive
 * @return      true if reception successful, false otherwise
 * @details     Receives specified amount of data from the connected socket. Handles endianness conversion if necessary.
 */
bool NetworkConnection::receiveData(uint8_t* const buffer, const size_t size) const
{
	if (!m_socket || !m_isConnected || !buffer || size == 0) {
		return false;
	}
	size_t bytesRemaining = size;
	uint8_t* currentPosition = buffer;
	while (bytesRemaining > 0)
	{
		uint8_t tempBuffer[DEFAULT_PACKET_SIZE] = { 0 };
		boost::system::error_code errorCode;
		size_t bytesRead = read(*m_socket, boost::asio::buffer(tempBuffer, DEFAULT_PACKET_SIZE), errorCode);
		if (errorCode || bytesRead == 0) {
			return false;
		}
		if (m_isBigEndian) {
			convertEndianness(tempBuffer, bytesRead);
		}
		const size_t bytesCopy = (bytesRemaining > bytesRead) ? bytesRead : bytesRemaining;
		memcpy(currentPosition, tempBuffer, bytesCopy);
		currentPosition += bytesCopy;
		bytesRemaining = (bytesRemaining < bytesCopy) ? 0 : (bytesRemaining - bytesCopy);
	}
	return true;
}

/**
 * @brief       Sends data through the socket
 * @param[in]   buffer    Buffer containing data to send
 * @param[in]   size      Size of data to send
 * @return      true if transmission successful, false otherwise
 * @details     Sends specified amount of data through the connected socket. Handles endianness conversion if necessary.
 */
bool NetworkConnection::sendData(const uint8_t* const buffer, const size_t size) const
{
	if (!m_socket || !m_isConnected || !buffer || size == 0) {
		return false;
	}
	size_t bytesRemaining = size;
	const uint8_t* currentPosition = buffer;
	while (bytesRemaining > 0) {
		uint8_t tempBuffer[DEFAULT_PACKET_SIZE] = { 0 };
		boost::system::error_code errorCode;
		const size_t bytesToSend = (bytesRemaining > DEFAULT_PACKET_SIZE) ? DEFAULT_PACKET_SIZE : bytesRemaining;
		memcpy(tempBuffer, currentPosition, bytesToSend);
		if (m_isBigEndian) {
			convertEndianness(tempBuffer, bytesToSend);
		}
		const size_t bytesWritten = write(*m_socket, boost::asio::buffer(tempBuffer, DEFAULT_PACKET_SIZE), errorCode);
		if (errorCode || bytesWritten == 0) {
			return false;
		}
		currentPosition += bytesWritten;
		bytesRemaining = (bytesRemaining < bytesWritten) ? 0 : (bytesRemaining - bytesWritten);
	}
	return true;
}

/**
 * @brief       Sends data and waits for response (request-response cycle)
 * @param[in]   sendBuffer    Buffer containing data to send
 * @param[in]   sendSize      Size of data to send
 * @param[out]  receiveBuffer Buffer to store received response
 * @param[in]   receiveSize   Size of response buffer
 * @return      true if exchange successful, false otherwise
 * @details     Performs complete request-response cycle by sending data and immediately waiting for response. Atomic operation.
 */
bool NetworkConnection::exchangeData(const uint8_t* const sendBuffer, const size_t sendSize, uint8_t* const receiveBuffer, const size_t receiveSize)
{
	if (!establishConnection()) {
		return false;
	}
	bool success = true;
	if (success && !sendData(sendBuffer, sendSize)) {
		success = false;
	}
	if (success && !receiveData(receiveBuffer, receiveSize)) {
		success = false;
	}
	disconnectSocket();
	return success;
}

// ================================
// Private Helper Methods
// ================================

/**
 * @brief       Converts data endianness if necessary
 * @param[in,out] buffer    Data buffer to convert
 * @param[in]     size      Size of data buffer
 * @details     Performs byte order conversion for cross-platform compatibility when system endianness differs from network.
 */
void NetworkConnection::convertEndianness(uint8_t* const buffer, size_t size) const
{
	if (!buffer || size < sizeof(uint32_t)) {
		return;
	}
	// Ensure we're working with complete 32-bit blocks
	size -= (size % sizeof(uint32_t));
	uint32_t* const wordPtr = reinterpret_cast<uint32_t* const>(buffer);
	for (size_t i = 0; i < size / sizeof(uint32_t); ++i)
	{
		const uint32_t currentValue = wordPtr[i];
		const uint32_t swap = ((currentValue << 8) & 0xFF00FF00) | ((currentValue >> 8) & 0xFF00FF);
		wordPtr[i] = (swap << 16) | (swap >> 16);
	}
}

/**
 * @brief       Validates port number format
 * @param[in]   port      Port string to validate
 * @return      true if port is valid, false otherwise
 * @details     Checks that port string represents a valid port number in the range 1-65535.
 */
bool NetworkConnection::validatePort(const std::string& port)
{
	try {
		const int portNum = std::stoi(port);
		return (portNum > 0 && portNum <= 65535);
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Validates IP address format
 * @param[in]   address   IP address string to validate
 * @return      true if address is valid, false otherwise
 * @details     Checks that address string represents a valid IPv4 or IPv6 address format. Accepts 'localhost'.
 */
bool NetworkConnection::validateAddress(const std::string& address)
{
	if ((address == "localhost") || (address == "LOCALHOST")) {
		return true;
	}
	try
	{
		(void)boost::asio::ip::make_address(address);
		return true;
	}
	catch (...) {
		return false;
	}
}