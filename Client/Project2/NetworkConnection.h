/**
 * @file        NetworkConnection.h
 * @author      Natanel Maor Fishman
 * @brief       TCP network connection manager for client-server communication
 * @details     Provides TCP socket communication with automatic endianness handling,
 *              connection management, and comprehensive error handling for secure messaging
 * @date        2025
 */

#pragma once
#include <string>
#include <cstdint>
#include <ostream>
#include <boost/asio/ip/tcp.hpp>

 // Use Boost ASIO for networking components
using boost::asio::io_context;
using boost::asio::ip::tcp;

/// Default packet size for network communications in bytes
constexpr size_t DEFAULT_PACKET_SIZE = 1024;

/**
 * @class       NetworkConnection
 * @brief       Advanced TCP network connection manager for secure client-server communication
 * @details     Provides comprehensive TCP socket management including connection establishment,
 *              data transmission, automatic endianness conversion, and robust error handling.
 *              Supports both blocking and non-blocking operations with automatic resource cleanup.
 *
 * @note        This class is non-copyable and non-movable to prevent socket resource conflicts
 *              and ensure proper connection state management.
 *
 * @warning     All network operations include comprehensive error handling and automatic
 *              resource cleanup to prevent memory leaks and connection issues.
 */
class NetworkConnection
{
public:
	/**
	 * @brief       Default constructor - initializes network connection manager
	 * @details     Creates a new network connection instance with automatic endianness detection
	 */
	NetworkConnection();

	/**
	 * @brief       Virtual destructor with automatic resource cleanup
	 * @details     Ensures proper cleanup of socket resources and network connections
	 */
	virtual ~NetworkConnection();

	/**
	 * @brief       Stream insertion operator for connection details
	 * @param[in,out] outputStream    Output stream to write connection details
	 * @param[in]     connectionPtr   Pointer to network connection
	 * @return      Reference to output stream
	 * @details     Outputs connection details in format "address:port"
	 */
	friend std::ostream& operator<<(std::ostream& outputStream, const NetworkConnection* connectionPtr) {
		if (connectionPtr != nullptr) {
			outputStream << connectionPtr->_remoteAddress << ':' << connectionPtr->_remotePort;
		}
		return outputStream;
	}

	/**
	 * @brief       Stream insertion operator for connection details
	 * @param[in,out] outputStream    Output stream to write connection details
	 * @param[in]     connection      Reference to network connection
	 * @return      Reference to output stream
	 * @details     Outputs connection details in format "address:port"
	 */
	friend std::ostream& operator<<(std::ostream& outputStream, const NetworkConnection& connection) {
		return operator<<(outputStream, &connection);
	}

	/**
	 * @brief       Establishes TCP connection to the configured endpoint
	 * @return      true if connection established successfully, false otherwise
	 * @details     Creates socket, resolves endpoint, and establishes connection with
	 *              automatic error handling and resource cleanup
	 */
	bool establishConnection();

	/**
	 * @brief       Safely closes the active network connection
	 * @details     Performs graceful shutdown, closes socket, and releases all resources.
	 *              Safe to call multiple times or when no connection is active.
	 */
	void disconnectSocket();

	/**
	 * @brief       Checks if the connection is currently active
	 * @return      true if connected, false otherwise
	 * @details     Returns the current connection state
	 */
	bool isConnected() const;

	/**
	 * @brief       Configures the remote endpoint for connection
	 * @param[in]   remoteAddress    IP address or hostname of remote endpoint
	 * @param[in]   remotePort       Port number for connection
	 * @return      true if endpoint configuration successful, false otherwise
	 * @details     Validates address and port before configuration
	 */
	bool configureEndpoint(const std::string& remoteAddress, const std::string& remotePort);

	/**
	 * @brief       Receives data from the network connection
	 * @param[out]  receiveBuffer    Buffer to store received data
	 * @param[in]   bufferSize       Number of bytes to receive
	 * @return      true if data received successfully, false otherwise
	 * @details     Receives specified number of bytes with automatic endianness conversion
	 */
	bool receiveData(uint8_t* receiveBuffer, size_t bufferSize) const;

	/**
	 * @brief       Sends data through the network connection
	 * @param[in]   sendBuffer       Buffer containing data to send
	 * @param[in]   bufferSize       Number of bytes to send
	 * @return      true if data sent successfully, false otherwise
	 * @details     Sends specified number of bytes with automatic endianness conversion
	 */
	bool sendData(const uint8_t* sendBuffer, size_t bufferSize) const;

	/**
	 * @brief       Performs complete send-receive exchange with automatic connection management
	 * @param[in]   sendBuffer       Buffer containing data to send
	 * @param[in]   sendSize         Number of bytes to send
	 * @param[out]  receiveBuffer    Buffer to store received response
	 * @param[in]   receiveSize      Number of bytes to receive
	 * @return      true if exchange completed successfully, false otherwise
	 * @details     Establishes connection, sends data, receives response, and disconnects
	 */
	bool exchangeData(const uint8_t* sendBuffer, size_t sendSize,
		uint8_t* receiveBuffer, size_t receiveSize);

	// Explicitly delete copy and move operations to prevent resource conflicts
	NetworkConnection(const NetworkConnection&) = delete;
	NetworkConnection(NetworkConnection&&) noexcept = delete;
	NetworkConnection& operator=(const NetworkConnection&) = delete;
	NetworkConnection& operator=(NetworkConnection&&) noexcept = delete;

private:
	io_context* _ioContext;      ///< Boost ASIO I/O context for network operations
	tcp::resolver* _resolver;    ///< DNS resolver for endpoint resolution
	tcp::socket* _socket;        ///< TCP socket for network communications
	std::string _remoteAddress;  ///< Remote endpoint IP address or hostname
	std::string _remotePort;     ///< Remote endpoint port number
	bool _isConnected;           ///< Current connection state flag
	bool _isBigEndian;           ///< System endianness detection flag

	/**
	 * @brief       Converts buffer endianness for network compatibility
	 * @param[in,out] buffer    Buffer to convert
	 * @param[in]     size      Size of buffer in bytes
	 * @details     Performs byte swapping for 32-bit words to ensure network compatibility
	 */
	void convertEndianness(uint8_t* buffer, size_t size) const;

	/**
	 * @brief       Validates port number format and range
	 * @param[in]   portString    Port number as string
	 * @return      true if port is valid, false otherwise
	 * @details     Validates port is numeric and within valid range (1-65535)
	 */
	static bool validatePort(const std::string& portString);

	/**
	 * @brief       Validates IP address or hostname format
	 * @param[in]   addressString    IP address or hostname as string
	 * @return      true if address is valid, false otherwise
	 * @details     Validates IPv4, IPv6, and hostname formats including localhost
	 */
	static bool validateAddress(const std::string& addressString);
};
// TODO: In the future maybe add namespace net{}
// I didn't want to change it for this assignment