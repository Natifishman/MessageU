/**
 * @author	Natanel Maor Fishman
 * @file	NetworkConnection.h
 * @brief	Handles Tocket communications for client-server architecture
 */
#pragma once
#include <string>
#include <cstdint>
#include <ostream>
#include <boost/asio/ip/tcp.hpp>

 // Use Boost ASIO for networking components
using boost::asio::io_context;
using boost::asio::ip::tcp;


// Default packet size for network communications
constexpr size_t DEFAULT_PACKET_SIZE = 1024;


class NetworkConnection
{
public:
	// Constructors and destructors
	NetworkConnection();            // Default constructor
	virtual ~NetworkConnection();	// Virtual destructor for inheritance support

	// Prevent copying and moving - socket resources cannot be safely duplicated
    NetworkConnection(const NetworkConnection&) = delete;
    NetworkConnection(NetworkConnection&&) noexcept = delete;
    NetworkConnection& operator=(const NetworkConnection&) = delete;
    NetworkConnection& operator=(NetworkConnection&&) noexcept = delete;

	//Stream insertion operator for connection details
	friend std::ostream& operator<<(std::ostream& os, const NetworkConnection* socket) {
		if (socket != nullptr)
			os << socket->m_address << ':' << socket->m_port;
		return os;
	}

	//Stream insertion operator for connection details
	friend std::ostream& operator<<(std::ostream& os, const NetworkConnection& socket) {
		return operator<<(os, &socket);
	}

	// Connection management
	bool establishConnection();                            // Establishes connection to the endpoint
	void disconnectSocket();                               // Closes the active connection
	bool isConnected() const;                              // Checks if the connection is active
	bool configureEndpoint(const std::string& address,     // Configures connection endpoint
		const std::string& port);

	// Data transfer methods
	bool receiveData(uint8_t* const buffer,                // Receives data from the socket
		const size_t size) const;
	bool sendData(const uint8_t* const buffer,             // Sends data through the socket
		const size_t size) const;
	bool exchangeData(const uint8_t* const toSend,         // Sends data and waits for response
		const size_t size, uint8_t* const response, const size_t resSize);

private:
	io_context* m_ioContext;      ///< Boost ASIO I/O context
	tcp::resolver* m_resolver;    ///< resolver
	tcp::socket* m_socket;        ///< socket for communications
	std::string m_address;        ///< Remote endpoint IP address
	std::string m_port;           ///< Remote endpoint port
	bool m_isConnected;           ///< Connection state flag
	bool m_isBigEndian;           ///< System endianness flag

	// Helper methods
	void convertEndianness(uint8_t* const buffer, size_t size) const;
	static bool validatePort(const std::string& port);
	static bool validateAddress(const std::string& address);
};
// TODO: In the future maybe add namespace net{}
// I didn't want to change it for this assignment