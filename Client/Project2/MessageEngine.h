/**
 * @author		Natanel Maor Fishman
 * @file		MessageEngine.h
 * @brief       Core messaging component for secure client communication
 * 
 * @details     Handles message processing, encryption, and coordination between
 *              the user interface and network/configuration subsystems
 */

#pragma once
#include "protocol.h"
#include <sstream>
#include <string>
#include <vector>

// Configuration file paths
constexpr auto CLIENT_INFO = "my.info";
constexpr auto SERVER_INFO = "server.info";

// Forward declarations
class ConfigManager;
class NetworkConnection;
class RSAPrivateWrapper;

class MessageEngine
{
public:

	struct ClientInfo
	{
		ClientIdStruct         id;				///< Unique client identifier
		std::string            username;		///< Client's display name
		PublicKeyStruct        publicKey;		///< RSA public key
		SymmetricKeyStruct     symmetricKey;	///< Session encryption key
		bool publicKeySet =	   false;			///< Flag indicating if public key is available
		bool symmetricKeySet = false;			///< Flag indicating if symmetric key is available
	};

	struct MessageData
	{
		std::string username;   ///< Source username
		std::string content;    ///< Message content
	};

public:
	// Constructor & Destructor
	MessageEngine();
	virtual ~MessageEngine();

	// Deleting copy/move constructors and assignment operators (secure handling of sensitive data)
    MessageEngine(const MessageEngine&) = delete;
    MessageEngine(MessageEngine&&) noexcept = delete;
    MessageEngine& operator=(const MessageEngine&) = delete;
    MessageEngine& operator=(MessageEngine&&) noexcept = delete;

	// Getters
	std::string getErrorMessage() const { return m_errorBuffer.str(); }
	std::string getSelfUsername() const { return m_localUser.username; }
	ClientIdStruct getSelfClientID() const { return m_localUser.id; }

	// Configuration
	bool loadServerConfiguration();                             // Loads server configuration
	bool loadUserCredentials();                                 // Loads user credentials

	// Client management
	bool registerClient(const std::string& username);           // Registers a new client
	std::vector<std::string> getUsernames() const;              // Gets list of usernames
	bool requestClientsList();                                  // Requests the list of clients
	bool requestClientPublicKey(const std::string& username);   // Requests a specific client's public key

	// Messaging
	bool sendMessage(const std::string& username, MessageTypeEnum type,
		const std::string& data = "");                      // Sends message to specified user
	bool retrievePendingMessages(std::vector<MessageData>& messages); // Gets pending messages

private:
	// Component interfaces
	NetworkConnection* _networkManager; ///< Network communication
	ConfigManager* _configManager;		///< Configuration storage
	RSAPrivateWrapper* _cryptoEngine;   ///< Encryption/decryption

	// Member variables
	ClientInfo				m_localUser;     ///< Current user's information
	std::vector<ClientInfo> m_peerRegistry;  ///< Known clients
	std::stringstream		m_errorBuffer;	 ///< Error message buffer

	// Client management
	bool findClientById(const ClientIdStruct& clientID, ClientInfo& client) const;      // Finds client by ID
	bool findClientByUsername(const std::string& username, ClientInfo& client) const;   // Finds client by username
	bool storeClientInfo();                                                             // Stores client information

	// Key management
	bool setClientPublicKey(const ClientIdStruct& clientID, const PublicKeyStruct& publicKey);          // Sets client's public key
	bool setClientSymmetricKey(const ClientIdStruct& clientID, const SymmetricKeyStruct& symmetricKey); // Sets client's symmetric key

	// Response handling
	bool validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode);        // Validates response header
	bool receiveUnknownPayload(const uint8_t* const request, const size_t reqSize,
		const ResponseCodeEnum expectedCode, uint8_t*& payload, size_t& size);    // Handles unknown payload

	// Resource management
	void cleanup();        ///< Releases allocated resources
	void clearLastError(); // Clears the last error
};
