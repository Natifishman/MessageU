/**
 * @file        NetworkConnection.h
 * @author      Natanel Maor Fishman
 * @brief       Network connection management for client-server communication
 * @details     Handles TCP socket communications for client-server architecture
 *              using Boost ASIO for robust networking capabilities.
 *              Provides connection management, data transfer, and endpoint configuration.
 * @version     2.0
 * @date        2025
 */

#pragma once

// ================================
// Standard Library Includes
// ================================

#include <string>
#include <cstdint>
#include <ostream>

// ================================
// Third-Party Includes
// ================================

#include <boost/asio/ip/tcp.hpp>

// ================================
// Using Declarations
// ================================

// Use Boost ASIO for networking components
using boost::asio::io_context;
using boost::asio::ip::tcp;

// ================================
// Constants
// ================================

// Default packet size for network communications
constexpr size_t DEFAULT_PACKET_SIZE = 1024;

// ================================
// Class Definition
// ================================

/**
 * @class       NetworkConnection
 * @brief       Network connection management class for client-server communication
 * @details     Provides comprehensive TCP socket management including connection
 *              establishment, data transfer, and endpoint configuration.
 *              Uses Boost ASIO for cross-platform networking capabilities.
 *              
 *              Features:
 *              - Connection state management
 *              - Bidirectional data transfer
 *              - Endpoint validation and configuration
 *              - Endianness handling for cross-platform compatibility
 *              - Resource management and cleanup
 *              
 * @note        This class is non-copyable and non-movable due to socket resource
 *              constraints. Socket resources cannot be safely duplicated.
 */
class NetworkConnection
{
public:
	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Default constructor - initializes network connection
	 * @details     Creates new network connection with uninitialized state.
	 *              All networking components are created but not connected.
	 */
	NetworkConnection();

	/**
	 * @brief       Virtual destructor with automatic cleanup
	 * @details     Ensures proper cleanup of all networking resources including
	 *              socket, resolver, and I/O context. Prevents resource leaks.
	 */
	virtual ~NetworkConnection();

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Prevent copying and moving - socket resources cannot be safely duplicated
    NetworkConnection(const NetworkConnection&) = delete;
    NetworkConnection(NetworkConnection&&) noexcept = delete;
    NetworkConnection& operator=(const NetworkConnection&) = delete;
    NetworkConnection& operator=(NetworkConnection&&) noexcept = delete;

	// ================================
	// Stream Operators
	// ================================

	/**
	 * @brief       Stream insertion operator for connection details (pointer version)
	 * @param[in,out] os      Output stream for connection information
	 * @param[in]     socket   Pointer to network connection
	 * @return      Reference to output stream
	 * @details     Outputs connection details in format "address:port"
	 */
	friend std::ostream& operator<<(std::ostream& os, const NetworkConnection* socket) {
		if (socket != nullptr)
			os << socket->m_address << ':' << socket->m_port;
		return os;
	}

	/**
	 * @brief       Stream insertion operator for connection details (reference version)
	 * @param[in,out] os      Output stream for connection information
	 * @param[in]     socket   Reference to network connection
	 * @return      Reference to output stream
	 * @details     Delegates to pointer version for consistent output formatting
	 */
	friend std::ostream& operator<<(std::ostream& os, const NetworkConnection& socket) {
		return operator<<(os, &socket);
	}

	// ================================
	// Connection Management Methods
	// ================================

	/**
	 * @brief       Establishes connection to the configured endpoint
	 * @return      true if connection successful, false otherwise
	 * @details     Attempts to establish TCP connection to the configured
	 *              address and port. Updates connection state accordingly.
	 */
	bool establishConnection();

	/**
	 * @brief       Closes the active connection
	 * @details     Gracefully closes the socket connection and updates
	 *              connection state. Ensures proper resource cleanup.
	 */
	void disconnectSocket();

	/**
	 * @brief       Checks if the connection is active
	 * @return      true if connected, false otherwise
	 * @details     Returns current connection state without performing
	 *              network operations.
	 */
	bool isConnected() const;

	/**
	 * @brief       Configures connection endpoint
	 * @param[in]   address   Remote endpoint IP address
	 * @param[in]   port      Remote endpoint port number
	 * @return      true if configuration successful, false otherwise
	 * @details     Validates and stores endpoint configuration for future
	 *              connection attempts. Does not establish connection.
	 */
	bool configureEndpoint(const std::string& address, const std::string& port);

	// ================================
	// Data Transfer Methods
	// ================================

	/**
	 * @brief       Receives data from the socket
	 * @param[out]  buffer    Buffer to store received data
	 * @param[in]   size      Size of data to receive
	 * @return      true if reception successful, false otherwise
	 * @details     Receives specified amount of data from the connected socket.
	 *              Handles endianness conversion if necessary.
	 */
	bool receiveData(uint8_t* const buffer, const size_t size) const;

	/**
	 * @brief       Sends data through the socket
	 * @param[in]   buffer    Buffer containing data to send
	 * @param[in]   size      Size of data to send
	 * @return      true if transmission successful, false otherwise
	 * @details     Sends specified amount of data through the connected socket.
	 *              Handles endianness conversion if necessary.
	 */
	bool sendData(const uint8_t* const buffer, const size_t size) const;

	/**
	 * @brief       Sends data and waits for response
	 * @param[in]   toSend    Buffer containing data to send
	 * @param[in]   size      Size of data to send
	 * @param[out]  response  Buffer to store received response
	 * @param[in]   resSize   Size of response buffer
	 * @return      true if exchange successful, false otherwise
	 * @details     Performs complete request-response cycle by sending data
	 *              and immediately waiting for response. Atomic operation.
	 */
	bool exchangeData(const uint8_t* const toSend, const size_t size, 
		uint8_t* const response, const size_t resSize);

private:
	// ================================
	// Member Variables
	// ================================

	io_context* m_ioContext;      ///< Boost ASIO I/O context for networking operations
	tcp::resolver* m_resolver;    ///< DNS resolver for endpoint resolution
	tcp::socket* m_socket;        ///< TCP socket for communications
	std::string m_address;        ///< Remote endpoint IP address
	std::string m_port;           ///< Remote endpoint port number
	bool m_isConnected;           ///< Connection state flag
	bool m_isBigEndian;           ///< System endianness flag for data conversion

	// ================================
	// Private Helper Methods
	// ================================

	/**
	 * @brief       Converts data endianness if necessary
	 * @param[in,out] buffer    Data buffer to convert
	 * @param[in]     size      Size of data buffer
	 * @details     Performs byte order conversion for cross-platform
	 *              compatibility when system endianness differs from network.
	 */
	void convertEndianness(uint8_t* const buffer, size_t size) const;

	/**
	 * @brief       Validates port number format
	 * @param[in]   port      Port string to validate
	 * @return      true if port is valid, false otherwise
	 * @details     Checks that port string represents a valid port number
	 *              in the range 1-65535.
	 */
	static bool validatePort(const std::string& port);

	/**
	 * @brief       Validates IP address format
	 * @param[in]   address   IP address string to validate
	 * @return      true if address is valid, false otherwise
	 * @details     Checks that address string represents a valid IPv4
	 *              or IPv6 address format.
	 */
	static bool validateAddress(const std::string& address);
};

// TODO: In the future maybe add namespace net{}
// I didn't want to change it for this assignment