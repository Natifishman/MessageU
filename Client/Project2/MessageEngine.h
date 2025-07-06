/**
 * @author		Natanel Maor Fishman
 * @file		MessageEngine.h
 * @brief       Core messaging component for secure client communication
 * 
 * @details     Handles message processing, encryption, and coordination between
 *              the user interface and network/configuration subsystems. This class
 *              serves as the central orchestrator for all client-server communication,
 *              managing cryptographic operations, client registration, and message
 *              exchange with robust error handling and resource management.
 */

#pragma once
#include "protocol.h"
#include <sstream>
#include <string>
#include <vector>

/**
 * @brief Configuration file paths for client and server information
 * @details These files store essential configuration data for client operation
 */
constexpr auto CLIENT_INFO = "my.info";    ///< Client credentials and private key file
constexpr auto SERVER_INFO = "server.info"; ///< Server connection configuration file

// Forward declarations
class ConfigManager;
class NetworkConnection;
class RSAPrivateWrapper;

/**
 * @class       MessageEngine
 * @brief       Central messaging and communication orchestrator
 * @details     MessageEngine is the primary component responsible for managing all
 *              client-server communication, including user registration, key exchange,
 *              message encryption/decryption, and coordination between various subsystems.
 *              It provides a high-level interface for the console interface while handling
 *              complex cryptographic operations and network communication internally.
 * 
 * @note        This class is non-copyable and non-movable to ensure proper resource
 *              management and prevent accidental sharing of sensitive cryptographic data.
 */
class MessageEngine
{
public:
	/**
	 * @brief Client information structure for peer management
	 * @details Stores complete information about a client including cryptographic keys
	 *          and connection state for secure communication
	 */
	struct ClientInfo
	{
		ClientIdStruct         id;				///< Unique client identifier (UUID)
		std::string            username;		///< Client's display name for user interface
		PublicKeyStruct        publicKey;		///< RSA public key for asymmetric encryption
		SymmetricKeyStruct     symmetricKey;	///< AES symmetric key for session encryption
		bool publicKeySet =	   false;			///< Flag indicating if public key is available
		bool symmetricKeySet = false;			///< Flag indicating if symmetric key is available
	};

	/**
	 * @brief Message data structure for user interface
	 * @details Contains decrypted message content and source information for display
	 */
	struct MessageData
	{
		std::string username;   ///< Source username for message attribution
		std::string content;    ///< Decrypted message content
	};

public:
	/**
	 * @brief Default constructor initializes MessageEngine subsystems
	 * @details Creates and initializes ConfigManager and NetworkConnection components.
	 *          Throws std::bad_alloc if memory allocation fails during initialization.
	 * @throws std::bad_alloc if subsystem initialization fails
	 */
	MessageEngine();

	/**
	 * @brief Virtual destructor with automatic resource cleanup
	 * @details Ensures proper cleanup of all allocated resources including cryptographic
	 *          components, network connections, and configuration managers
	 */
	virtual ~MessageEngine();

	/**
	 * @brief Deleted copy constructor for security
	 * @details Prevents accidental copying of sensitive cryptographic data
	 */
	MessageEngine(const MessageEngine&) = delete;

	/**
	 * @brief Deleted move constructor for security
	 * @details Prevents accidental moving of sensitive cryptographic data
	 */
	MessageEngine(MessageEngine&&) noexcept = delete;

	/**
	 * @brief Deleted copy assignment operator for security
	 * @details Prevents accidental assignment of sensitive cryptographic data
	 */
	MessageEngine& operator=(const MessageEngine&) = delete;

	/**
	 * @brief Deleted move assignment operator for security
	 * @details Prevents accidental assignment of sensitive cryptographic data
	 */
	MessageEngine& operator=(MessageEngine&&) noexcept = delete;

	// ==================== GETTER METHODS ====================

	/**
	 * @brief Retrieves the current error message from the error buffer
	 * @return String containing the last error message or empty string if no error
	 * @details Returns the accumulated error message from the internal string stream
	 */
	std::string getErrorMessage() const { return m_errorBuffer.str(); }

	/**
	 * @brief Retrieves the current user's username
	 * @return String containing the local user's display name
	 * @details Returns the username loaded from the client configuration file
	 */
	std::string getSelfUsername() const { return m_localUser.username; }

	/**
	 * @brief Retrieves the current user's client identifier
	 * @return ClientIdStruct containing the local user's UUID
	 * @details Returns the client ID assigned during registration or loaded from config
	 */
	ClientIdStruct getSelfClientID() const { return m_localUser.id; }

	// ==================== CONFIGURATION METHODS ====================

	/**
	 * @brief Loads server connection configuration from file
	 * @return true if configuration loaded successfully, false otherwise
	 * @details Parses server address and port from server.info file and configures
	 *          the network connection component for communication
	 */
	bool loadServerConfiguration();

	/**
	 * @brief Loads user credentials and cryptographic keys from file
	 * @return true if credentials loaded successfully, false otherwise
	 * @details Reads username, UUID, and private key from my.info file and initializes
	 *          the RSA cryptographic engine for secure communication
	 */
	bool loadUserCredentials();

	// ==================== CLIENT MANAGEMENT METHODS ====================

	/**
	 * @brief Registers a new client with the server
	 * @param[in] username Display name for the new client
	 * @return true if registration successful, false otherwise
	 * @details Sends registration request to server with username and public key,
	 *          receives assigned client ID and stores it locally
	 */
	bool registerClient(const std::string& username);

	/**
	 * @brief Retrieves sorted list of all registered usernames
	 * @return Vector of usernames sorted alphabetically
	 * @details Returns usernames from the local peer registry, sorted for display
	 */
	std::vector<std::string> getUsernames() const;

	/**
	 * @brief Requests updated list of registered clients from server
	 * @return true if request successful, false otherwise
	 * @details Sends clients list request to server and updates local peer registry
	 *          with current client information
	 */
	bool requestClientsList();

	/**
	 * @brief Requests public key for a specific client
	 * @param[in] username Target client's username
	 * @return true if request successful, false otherwise
	 * @details Sends public key request to server and stores the received key
	 *          in the local peer registry for future secure communication
	 */
	bool requestClientPublicKey(const std::string& username);

	// ==================== MESSAGING METHODS ====================

	/**
	 * @brief Sends encrypted message to specified user
	 * @param[in] username Target recipient's username
	 * @param[in] type Type of message (text, file, key exchange)
	 * @param[in] data Optional message content (empty for key requests)
	 * @return true if message sent successfully, false otherwise
	 * @details Handles complete message encryption, transmission, and confirmation
	 *          including automatic key exchange if necessary
	 */
	bool sendMessage(const std::string& username, MessageTypeEnum type,
		const std::string& data = "");

	/**
	 * @brief Retrieves and decrypts pending messages from server
	 * @param[out] messages Vector to store decrypted message data
	 * @return true if retrieval successful, false otherwise
	 * @details Requests pending messages from server, decrypts them using appropriate
	 *          keys, and populates the messages vector with readable content
	 */
	bool retrievePendingMessages(std::vector<MessageData>& messages);

private:
	// ==================== COMPONENT INTERFACES ====================
	NetworkConnection* _networkManager; ///< Network communication component
	ConfigManager* _configManager;		///< Configuration and file I/O component
	RSAPrivateWrapper* _cryptoEngine;   ///< RSA encryption/decryption component

	// ==================== MEMBER VARIABLES ====================
	ClientInfo				m_localUser;     ///< Current user's information and keys
	std::vector<ClientInfo> m_peerRegistry;  ///< Registry of known clients and their keys
	std::stringstream		m_errorBuffer;	 ///< Error message accumulation buffer

	// ==================== PRIVATE CLIENT MANAGEMENT METHODS ====================

	/**
	 * @brief Finds client information by UUID in peer registry
	 * @param[in] clientID UUID to search for
	 * @param[out] client Reference to store found client information
	 * @return true if client found, false otherwise
	 * @details Searches the peer registry for a client with matching UUID
	 */
	bool findClientById(const ClientIdStruct& clientID, ClientInfo& client) const;

	/**
	 * @brief Finds client information by username in peer registry
	 * @param[in] username Username to search for
	 * @param[out] client Reference to store found client information
	 * @return true if client found, false otherwise
	 * @details Searches the peer registry for a client with matching username
	 */
	bool findClientByUsername(const std::string& username, ClientInfo& client) const;

	/**
	 * @brief Stores current client information to configuration file
	 * @return true if storage successful, false otherwise
	 * @details Writes username, UUID, and private key to my.info file for persistence
	 */
	bool storeClientInfo();

	// ==================== PRIVATE KEY MANAGEMENT METHODS ====================

	/**
	 * @brief Sets public key for a specific client in peer registry
	 * @param[in] clientID Target client's UUID
	 * @param[in] publicKey RSA public key to store
	 * @return true if key stored successfully, false otherwise
	 * @details Updates the peer registry with the client's public key and sets
	 *          the publicKeySet flag to true
	 */
	bool setClientPublicKey(const ClientIdStruct& clientID, const PublicKeyStruct& publicKey);

	/**
	 * @brief Sets symmetric key for a specific client in peer registry
	 * @param[in] clientID Target client's UUID
	 * @param[in] symmetricKey AES symmetric key to store
	 * @return true if key stored successfully, false otherwise
	 * @details Updates the peer registry with the client's symmetric key and sets
	 *          the symmetricKeySet flag to true
	 */
	bool setClientSymmetricKey(const ClientIdStruct& clientID, const SymmetricKeyStruct& symmetricKey);

	// ==================== PRIVATE RESPONSE HANDLING METHODS ====================

	/**
	 * @brief Validates response header against expected response code
	 * @param[in] header Response header to validate
	 * @param[in] expectedCode Expected response code for this operation
	 * @return true if header is valid, false otherwise
	 * @details Checks protocol version and response code for consistency
	 */
	bool validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode);

	/**
	 * @brief Handles reception of unknown payload size
	 * @param[in] request Pointer to request data
	 * @param[in] reqSize Size of request data
	 * @param[in] expectedCode Expected response code
	 * @param[out] payload Reference to payload pointer (allocated by function)
	 * @param[out] size Reference to payload size
	 * @return true if payload received successfully, false otherwise
	 * @details Receives variable-length payload and allocates memory for it
	 */
	bool receiveUnknownPayload(const uint8_t* const request, const size_t reqSize,
		const ResponseCodeEnum expectedCode, uint8_t*& payload, size_t& size);

	// ==================== PRIVATE RESOURCE MANAGEMENT METHODS ====================

	/**
	 * @brief Releases all allocated resources
	 * @details Deletes all component pointers and resets them to nullptr
	 */
	void cleanup();

	/**
	 * @brief Clears the error message buffer
	 * @details Resets the internal string stream to empty state
	 */
	void clearLastError();
};
