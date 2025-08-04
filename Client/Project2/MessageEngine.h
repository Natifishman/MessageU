/**
 * @file        MessageEngine.h
 * @author      Natanel Maor Fishman
 * @brief       Core messaging component for secure client communication
 * @details     Handles message processing, encryption, and coordination between
 *              the user interface and network/configuration subsystems.
 *              Provides comprehensive message handling, key management, and client operations.
 * @version     2.0
 * @date        2025
 */

#pragma once

// Standard library includes
#include <sstream>
#include <string>
#include <vector>

// Application includes
#include "protocol.h"
#include "CryptoManager.h"
#include "MessageProcessor.h"
#include "ClientRegistry.h"

// ================================
// Constants
// ================================

// Configuration file paths
constexpr auto CLIENT_INFO = "my.info";
constexpr auto SERVER_INFO = "server.info";

// ================================
// Forward Declarations
// ================================

class ConfigManager;
class NetworkConnection;

/**
 * @class       MessageEngine
 * @brief       Core messaging engine for secure client communication
 * @details     Central component that manages all messaging operations including
 *              client registration, message sending/receiving, key management,
 *              and coordination between UI, network, and configuration subsystems.
 *              Provides secure communication with encryption and authentication.
 */
class MessageEngine
{
public:
	// ================================
	// Data Structures
	// ================================

	// Use ClientInfo from ClientRegistry
	using ClientInfo = ClientRegistry::ClientInfo;

	// Use ProcessedMessage from MessageProcessor
	using MessageData = MessageProcessor::ProcessedMessage;

public:
	// ================================
	// Constructor and Destructor
	// ================================

	/**
	 * @brief       Default constructor - initializes messaging engine
	 * @details     Creates new messaging engine with uninitialized state.
	 *              Component interfaces are created and initialized.
	 */
	MessageEngine();

	/**
	 * @brief       Virtual destructor with automatic cleanup
	 * @details     Ensures proper cleanup of all allocated resources and
	 *              secure handling of sensitive cryptographic data.
	 */
	virtual ~MessageEngine();

	// ================================
	// Copy Control (Deleted)
	// ================================

	// Deleting copy/move constructors and assignment operators (secure handling of sensitive data)
    MessageEngine(const MessageEngine&) = delete;
    MessageEngine(MessageEngine&&) noexcept = delete;
    MessageEngine& operator=(const MessageEngine&) = delete;
    MessageEngine& operator=(MessageEngine&&) noexcept = delete;

	// ================================
	// Public Interface Methods
	// ================================

	// Configuration Management
	/**
	 * @brief       Loads server configuration from file
	 * @return      true if configuration loaded successfully, false otherwise
	 * @details     Reads server connection parameters and validates configuration
	 */
	bool loadServerConfiguration();

	/**
	 * @brief       Loads user credentials from file
	 * @return      true if credentials loaded successfully, false otherwise
	 * @details     Reads user authentication data and validates credentials
	 */
	bool loadUserCredentials();

	// Client Management
	/**
	 * @brief       Registers a new client with the server
	 * @param[in]   username    Username for the new account
	 * @return      true if registration successful, false otherwise
	 * @details     Creates new user account with cryptographic key generation
	 */
	bool registerClient(const std::string& username);

	/**
	 * @brief       Gets list of registered usernames
	 * @return      Vector of available usernames
	 * @details     Returns cached list of registered users
	 */
	std::vector<std::string> getUsernames() const;

	/**
	 * @brief       Requests the list of clients from server
	 * @return      true if request successful, false otherwise
	 * @details     Updates internal client registry with server data
	 */
	bool requestClientsList();

	/**
	 * @brief       Requests a specific client's public key
	 * @param[in]   username    Username of target client
	 * @return      true if request successful, false otherwise
	 * @details     Retrieves and stores public key for secure communication
	 */
	bool requestClientPublicKey(const std::string& username);

	// Messaging Operations
	/**
	 * @brief       Sends message to specified user
	 * @param[in]   username    Target username
	 * @param[in]   type        Message type (text, file, key request, etc.)
	 * @param[in]   data        Optional message data
	 * @return      true if message sent successfully, false otherwise
	 * @details     Encrypts and sends message with appropriate protocol handling
	 */
	bool sendMessage(const std::string& username, MessageTypeEnum type,
		const std::string& data = "");

	/**
	 * @brief       Retrieves pending messages from server
	 * @param[out]  messages    Vector to store retrieved messages
	 * @return      true if retrieval successful, false otherwise
	 * @details     Decrypts and formats messages for user display
	 */
	bool retrievePendingMessages(std::vector<MessageData>& messages);

	// ================================
	// Accessor Methods
	// ================================

	/**
	 * @brief       Gets the last error message
	 * @return      Error message string
	 * @details     Returns formatted error information for user feedback
	 */
	std::string getErrorMessage() const { return m_errorBuffer.str(); }

	/**
	 * @brief       Gets the current user's username
	 * @return      Username string
	 * @details     Returns authenticated user's display name
	 */
	std::string getSelfUsername() const { return m_localUser.username; }

	/**
	 * @brief       Gets the current user's client ID
	 * @return      Client ID structure
	 * @details     Returns unique identifier for current user
	 */
	ClientIdStruct getSelfClientID() const { return m_localUser.id; }

private:
	// ================================
	// Member Variables
	// ================================

	// Component interfaces
	NetworkConnection* _networkManager;   ///< Network communication manager
	ConfigManager* _configManager;		  ///< Configuration storage manager
	CryptoManager* _cryptoManager;		  ///< Cryptographic operations manager
	MessageProcessor* _messageProcessor;  ///< Message processing component
	ClientRegistry* _clientRegistry;	  ///< Client information registry

	// Data storage
	ClientInfo				m_localUser;     ///< Current user's information
	std::stringstream		m_errorBuffer;	 ///< Error message buffer

	// ================================
	// Private Helper Methods
	// ================================

	// Client Management
	/**
	 * @brief       Stores client information in registry
	 * @return      true if storage successful, false otherwise
	 * @details     Updates internal client registry with new information
	 */
	bool storeClientInfo();

	// Response Handling
	/**
	 * @brief       Validates response header from server
	 * @param[in]   header        Response header to validate
	 * @param[in]   expectedCode  Expected response code
	 * @return      true if header valid, false otherwise
	 * @details     Verifies response format and expected status code
	 */
	bool validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode);

	/**
	 * @brief       Handles unknown payload from server
	 * @param[in]   request       Original request data
	 * @param[in]   reqSize       Request size
	 * @param[in]   expectedCode  Expected response code
	 * @param[out]  payload       Received payload data
	 * @param[out]  size          Payload size
	 * @return      true if payload handled successfully, false otherwise
	 * @details     Processes variable-length payload with proper validation
	 */
	bool receiveUnknownPayload(const uint8_t* const request, const size_t reqSize,
		const ResponseCodeEnum expectedCode, uint8_t*& payload, size_t& size);

	// Resource Management
	/**
	 * @brief       Releases allocated resources
	 * @details     Cleans up all component interfaces and sensitive data
	 */
	void cleanup();

	/**
	 * @brief       Clears the last error message
	 * @details     Resets error buffer for new operations
	 */
	void clearLastError();
};
