/**
 * @file        NetworkConnection.cpp
 * @author      Natanel Maor Fishman
 * @brief       TCP network connection manager implementation
 * @details     Implementation of TCP socket communication with automatic endianness
 *              handling, connection management, and comprehensive error handling
 * @date        2025
 */

#include "NetworkConnection.h"
#include <boost/asio.hpp>
#include <stdexcept>
#include <algorithm>

using boost::asio::ip::tcp;
using boost::asio::io_context;

/**
 * @brief       Default constructor - initializes network connection manager
 * @details     Creates a new network connection instance with automatic endianness detection
 *              using union-based approach for cross-platform compatibility
 */
NetworkConnection::NetworkConnection()
	: _ioContext(nullptr), _resolver(nullptr), _socket(nullptr), _isConnected(false)
{
	// Detect system endianness using union approach for cross-platform compatibility
	union {
		uint32_t integerValue;
		uint8_t byteArray[sizeof(uint32_t)];
	} endiannessTest{ 1 };

	_isBigEndian = (endiannessTest.byteArray[0] == 0);
}

/**
 * @brief       Virtual destructor with automatic resource cleanup
 * @details     Ensures proper cleanup of socket resources and network connections
 */
NetworkConnection::~NetworkConnection()
{
	disconnectSocket();
}

/**
 * @brief       Configures the remote endpoint for connection
 * @param[in]   remoteAddress    IP address or hostname of remote endpoint
 * @param[in]   remotePort       Port number for connection
 * @return      true if endpoint configuration successful, false otherwise
 * @details     Validates address and port before configuration to ensure valid endpoint
 */
bool NetworkConnection::configureEndpoint(const std::string& remoteAddress, const std::string& remotePort)
{
	// Validate address and port before setting configuration
	if (!validateAddress(remoteAddress) || !validatePort(remotePort)) {
		return false;
	}

	// Set the remote endpoint configuration
	_remoteAddress = remoteAddress;
	_remotePort = remotePort;
	return true;
}

/**
 * @brief       Validates IP address or hostname format
 * @param[in]   addressString    IP address or hostname as string
 * @return      true if address is valid, false otherwise
 * @details     Validates IPv4, IPv6, and hostname formats including localhost
 */
bool NetworkConnection::validateAddress(const std::string& addressString)
{
	// Special case handling for localhost variations
	if ((addressString == "localhost") || (addressString == "LOCALHOST")) {
		return true;
	}

	try {
		// Use Boost ASIO to validate address format
		(void)boost::asio::ip::make_address(addressString);
		return true;
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Validates port number format and range
 * @param[in]   portString    Port number as string
 * @return      true if port is valid, false otherwise
 * @details     Validates port is numeric and within valid range (1-65535)
 */
bool NetworkConnection::validatePort(const std::string& portString)
{
	try {
		const int portNumber = std::stoi(portString);

		// Port must be between 1 and 65535 (valid TCP port range)
		return (portNumber > 0 && portNumber <= 65535);
	}
	catch (...) {
		return false;
	}
}

/**
 * @brief       Establishes TCP connection to the configured endpoint
 * @return      true if connection established successfully, false otherwise
 * @details     Creates socket, resolves endpoint, and establishes connection with
 *              automatic error handling and resource cleanup
 */
bool NetworkConnection::establishConnection()
{
	// Validate endpoint configuration before attempting connection
	if (!validateAddress(_remoteAddress) || !validatePort(_remotePort)) {
		return false;
	}

	try {
		// Ensure clean state before establishing new connection
		disconnectSocket();

		// Initialize Boost ASIO components for network operations
		_ioContext = new io_context;
		_resolver = new tcp::resolver(*_ioContext);
		_socket = new tcp::socket(*_ioContext);

		// Resolve endpoint and establish connection
		auto endpointList = _resolver->resolve(_remoteAddress, _remotePort);
		boost::asio::connect(*_socket, endpointList);

		// Configure socket for optimal performance
		_socket->set_option(tcp::no_delay(true));  // Disable Nagle's algorithm
		_socket->non_blocking(false);              // Use blocking mode for simplicity

		_isConnected = true;
		return true;
	}
	catch (...) {
		// Comprehensive error handling - reset connection state on any exception
		_isConnected = false;
		return false;
	}
}

/**
 * @brief       Safely closes the active network connection
 * @details     Performs graceful shutdown, closes socket, and releases all resources.
 *              Safe to call multiple times or when no connection is active.
 */
void NetworkConnection::disconnectSocket()
{
	try {
		// Perform graceful shutdown if socket is open
		if (_socket != nullptr && _socket->is_open()) {
			boost::system::error_code shutdownError;
			_socket->shutdown(tcp::socket::shutdown_both, shutdownError);
			_socket->close();
		}
	}
	catch (...) {
		// Silent error handling for shutdown operations
	}

	// Clean up all allocated resources
	if (_socket != nullptr) {
		delete _socket;
		_socket = nullptr;
	}

	if (_resolver != nullptr) {
		delete _resolver;
		_resolver = nullptr;
	}

	if (_ioContext != nullptr) {
		delete _ioContext;
		_ioContext = nullptr;
	}

	_isConnected = false;
}

/**
 * @brief       Receives data from the network connection
 * @param[out]  receiveBuffer    Buffer to store received data
 * @param[in]   bufferSize       Number of bytes to receive
 * @return      true if data received successfully, false otherwise
 * @details     Receives specified number of bytes with automatic endianness conversion
 *              and comprehensive error handling
 */
bool NetworkConnection::receiveData(uint8_t* receiveBuffer, size_t bufferSize) const
{
	// Validate input parameters and connection state
	if (!_socket || !_isConnected || !receiveBuffer || bufferSize == 0) {
		return false;
	}

	size_t bytesRemaining = bufferSize;
	uint8_t* currentBufferPosition = receiveBuffer;

	// Receive data in chunks to handle large transfers
	while (bytesRemaining > 0) {
		uint8_t temporaryBuffer[DEFAULT_PACKET_SIZE] = { 0 };
		boost::system::error_code receiveError;

		// Read data from socket with error handling
		size_t bytesRead = read(*_socket, boost::asio::buffer(temporaryBuffer, DEFAULT_PACKET_SIZE), receiveError);

		if (receiveError || bytesRead == 0) {
			return false;  // Connection error or EOF
		}

		// Convert endianness if system is big-endian
		if (_isBigEndian) {
			convertEndianness(temporaryBuffer, bytesRead);
		}

		// Copy received data to destination buffer with overflow protection
		const size_t bytesToCopy = (bytesRemaining > bytesRead) ? bytesRead : bytesRemaining;
		memcpy(currentBufferPosition, temporaryBuffer, bytesToCopy);
		currentBufferPosition += bytesToCopy;
		bytesRemaining = (bytesRemaining < bytesToCopy) ? 0 : (bytesRemaining - bytesToCopy);
	}

	return true;
}

/**
 * @brief       Sends data through the network connection
 * @param[in]   sendBuffer       Buffer containing data to send
 * @param[in]   bufferSize       Number of bytes to send
 * @return      true if data sent successfully, false otherwise
 * @details     Sends specified number of bytes with automatic endianness conversion
 *              and comprehensive error handling
 */
bool NetworkConnection::sendData(const uint8_t* sendBuffer, size_t bufferSize) const
{
	// Validate input parameters and connection state
	if (!_socket || !_isConnected || !sendBuffer || bufferSize == 0) {
		return false;
	}

	size_t bytesRemaining = bufferSize;
	const uint8_t* currentBufferPosition = sendBuffer;

	// Send data in chunks to handle large transfers
	while (bytesRemaining > 0) {
		uint8_t temporaryBuffer[DEFAULT_PACKET_SIZE] = { 0 };
		boost::system::error_code sendError;

		// Determine chunk size for this transmission
		const size_t bytesToSend = (bytesRemaining > DEFAULT_PACKET_SIZE) ? DEFAULT_PACKET_SIZE : bytesRemaining;
		memcpy(temporaryBuffer, currentBufferPosition, bytesToSend);

		// Convert endianness if system is big-endian
		if (_isBigEndian) {
			convertEndianness(temporaryBuffer, bytesToSend);
		}

		// Write data to socket with error handling
		const size_t bytesWritten = write(*_socket, boost::asio::buffer(temporaryBuffer, DEFAULT_PACKET_SIZE), sendError);
		if (sendError || bytesWritten == 0) {
			return false;  // Connection error
		}

		currentBufferPosition += bytesWritten;
		bytesRemaining = (bytesRemaining < bytesWritten) ? 0 : (bytesRemaining - bytesWritten);
	}

	return true;
}

/**
 * @brief       Performs complete send-receive exchange with automatic connection management
 * @param[in]   sendBuffer       Buffer containing data to send
 * @param[in]   sendSize         Number of bytes to send
 * @param[out]  receiveBuffer    Buffer to store received response
 * @param[in]   receiveSize      Number of bytes to receive
 * @return      true if exchange completed successfully, false otherwise
 * @details     Establishes connection, sends data, receives response, and disconnects
 *              with comprehensive error handling
 */
bool NetworkConnection::exchangeData(const uint8_t* sendBuffer, size_t sendSize,
	uint8_t* receiveBuffer, size_t receiveSize)
{
	// Establish connection for the exchange
	if (!establishConnection()) {
		return false;
	}

	bool exchangeSuccess = true;  // Track overall exchange success

	// Send data if connection established successfully
	if (exchangeSuccess && !sendData(sendBuffer, sendSize)) {
		exchangeSuccess = false;
	}

	// Receive response if send was successful
	if (exchangeSuccess && !receiveData(receiveBuffer, receiveSize)) {
		exchangeSuccess = false;
	}

	// Always disconnect after exchange attempt
	disconnectSocket();
	return exchangeSuccess;
}

/**
 * @brief       Converts buffer endianness for network compatibility
 * @param[in,out] buffer    Buffer to convert
 * @param[in]     size      Size of buffer in bytes
 * @details     Performs byte swapping for 32-bit words to ensure network compatibility
 *              Uses efficient bitwise operations for optimal performance
 */
void NetworkConnection::convertEndianness(uint8_t* buffer, size_t size) const
{
	// Validate input parameters
	if (!buffer || size < sizeof(uint32_t)) {
		return;
	}

	// Ensure we're working with complete 32-bit blocks
	size -= (size % sizeof(uint32_t));
	uint32_t* const wordPointer = reinterpret_cast<uint32_t* const>(buffer);

	// Swap bytes for each 32-bit word using efficient bitwise operations
	for (size_t wordIndex = 0; wordIndex < size / sizeof(uint32_t); ++wordIndex) {
		const uint32_t currentWord = wordPointer[wordIndex];

		// Efficient byte swapping using bitwise operations
		const uint32_t swappedBytes = ((currentWord << 8) & 0xFF00FF00) | ((currentWord >> 8) & 0xFF00FF);
		wordPointer[wordIndex] = (swappedBytes << 16) | (swappedBytes >> 16);
	}
}

/**
 * @brief       Checks if the connection is currently active
 * @return      true if connected, false otherwise
 * @details     Returns the current connection state
 */
bool NetworkConnection::isConnected() const
{
	return _isConnected;
}