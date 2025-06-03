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

// Constructor
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

// Default destructor
NetworkConnection::~NetworkConnection()
{
	disconnectSocket();
}

// Set the address and port for the connection.
bool NetworkConnection::configureEndpoint(const std::string& address, const std::string& port)
{
	// Validate address and port before setting
	if (!validateAddress(address) || !validatePort(port)) {
		return false;
	}

	// Set the address and port
	m_address = address;
	m_port = port;
	return true;
}


// IP Address parse attempt
bool NetworkConnection::validateAddress(const std::string& address)
{
	// Special case for localhost
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


// Parse port number attempt
bool NetworkConnection::validatePort(const std::string& port)
{
	try {
		const int portNum = std::stoi(port);

		// Port must be between 1 and 65535
		return (portNum > 0 && portNum <= 65535);
	}
	catch (...) {
		return false;
	}
}

// Establish connection with the server
bool NetworkConnection::establishConnection()
{
	if (!validateAddress(m_address) || !validatePort(m_port)) {
		return false;
	}

	try
	{
		// Ensure clean state before connecting
		disconnectSocket();

		// Reinitialize components
		m_ioContext = new io_context;
		m_resolver = new tcp::resolver(*m_ioContext);
		m_socket = new tcp::socket(*m_ioContext);

		// Connect to endpoint
		auto endpoints = m_resolver->resolve(m_address, m_port);
		boost::asio::connect(*m_socket, endpoints);

		// Configure socket options
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

// Disconnect from the server
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

	// Cleanup resources
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
 * Receive size bytes from m_socket to buffer.
 * Return false if unable to receive expected size bytes.
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
			return false;     // Error. do not use buffer.
		}

		// Copy data to buffer (small - big endian)
		if (m_isBigEndian) 
		{
			convertEndianness(tempBuffer, bytesRead);
		}

		// buffer overflow protection
		const size_t bytesCopy = (bytesRemaining > bytesRead) ? bytesRead : bytesRemaining;
		memcpy(currentPosition, tempBuffer, bytesCopy);
		currentPosition += bytesCopy;
		bytesRemaining = (bytesRemaining < bytesCopy) ? 0 : (bytesRemaining - bytesCopy);
	}

	return true;
}

/**
 * Send size bytes from buffer to m_socket.
 * Return false if unable to send expected size bytes.
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

		// Convert to big endian if needed
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

// Wrap functions (close/connect/send/receive)
bool NetworkConnection::exchangeData(const uint8_t* const sendBuffer, const size_t sendSize, uint8_t* const receiveBuffer, const size_t receiveSize)
{
	if (!establishConnection()) {
		return false;
	}

	bool success = true; //flag

	if (success && !sendData(sendBuffer, sendSize)) {
		success = false;
	}

	if (success && !receiveData(receiveBuffer, receiveSize)) {
		success = false;
	}

	disconnectSocket();
	return success;
}

// Convert endianness for buffer
void NetworkConnection::convertEndianness(uint8_t* const buffer, size_t size) const
{
	if (!buffer || size < sizeof(uint32_t)) {
		return;
	}

	// Ensure we're working with complete 32-bit blocks
	size -= (size % sizeof(uint32_t));
	uint32_t* const wordPtr = reinterpret_cast<uint32_t* const>(buffer);

	// Swap bytes for each 32-bit word
	for (size_t i = 0; i < size / sizeof(uint32_t); ++i)
	{
		const uint32_t currentValue = wordPtr[i];
		// Swap bytes using bitwise operations (efficient byte swapping)
		const uint32_t swap = ((currentValue << 8) & 0xFF00FF00) | ((currentValue >> 8) & 0xFF00FF);
		wordPtr[i] = (swap << 16) | (swap >> 16);
	}
}

bool NetworkConnection::isConnected() const
{
	return m_isConnected;
}