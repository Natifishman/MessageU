/**
 * @author		Natanel Maor Fishman
 * @file		MessageEngine.cpp
 * @brief       Client's primary message processing and coordination component.
 * @note        MessageEngine orchestrates communication between the console interface
 *              and backend subsystems including configuration management and network communication layers.
 * @details     This implementation provides the complete messaging functionality including
 *              client registration, key exchange, message encryption/decryption, and server
 *              communication with robust error handling and resource management.
 */
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "MessageEngine.h"
#include "StringUtility.h"
#include "ConfigManager.h"
#include "NetworkConnection.h"
#include <limits>

/**
 * @brief Stream operator for MessageType enumeration serialization
 * @param[in,out] os Output stream to write to
 * @param[in] type Message type to serialize
 * @return Reference to the output stream
 * @details Casts the enumeration to its underlying type for network transmission
 */
std::ostream& operator<<(std::ostream& os, const MessageTypeEnum& type)
{
	// Cast enumeration to underlying type for serialization
	os << static_cast<messageType_t>(type);
	return os;
}

/**
 * @brief Constructs a new MessageEngine with initialized subsystems
 * @details Creates and initializes ConfigManager and NetworkConnection components.
 *          Throws std::bad_alloc if memory allocation fails during initialization.
 * @throws std::bad_alloc if subsystem initialization fails
 */
MessageEngine::MessageEngine() : _configManager(nullptr), _networkManager(nullptr), _cryptoEngine(nullptr)
{
	try {
		// Initialize subsystem components
		_configManager = new ConfigManager();
		_networkManager = new NetworkConnection();
	}
	catch (const std::bad_alloc& e) {
		// Handle resource allocation failures
		clearLastError();
		m_errorBuffer << "Failed to initialize MessageEngine: " << e.what();

		// Clean up resources to prevent memory leaks
		cleanup();

		// Propagate the exception
		throw;
	}
}

/**
 * @brief Virtual destructor with automatic resource cleanup
 * @details Ensures proper cleanup of all allocated resources including cryptographic
 *          components, network connections, and configuration managers
 */
MessageEngine::~MessageEngine() {
	cleanup();
}

/**
 * @brief Releases all allocated resources in optimal order
 * @details Deletes all component pointers and resets them to nullptr to prevent
 *          double-deletion and ensure proper cleanup
 */
void MessageEngine::cleanup() {
	// Release resources in optimal order (reverse of allocation)
	if (_cryptoEngine) {
		delete _cryptoEngine;
		_cryptoEngine = nullptr;
	}

	if (_networkManager) {
		delete _networkManager;
		_networkManager = nullptr;
	}

	if (_configManager) {
		delete _configManager;
		_configManager = nullptr;
	}
}

/**
 * @brief Parses server connection information from configuration file
 * @return true if configuration loaded successfully, false otherwise
 * @details Reads server address and port from server.info file and configures
 *          the network connection component for communication
 */
bool MessageEngine::loadServerConfiguration()
{
	// Open server configuration file for reading
	if (!_configManager->openFile(SERVER_INFO))
	{
		clearLastError();
		m_errorBuffer << "Failed to open server configuration file: " << SERVER_INFO;
		return false;
	}

	// Read server connection string
	std::string serverData;
	if (!_configManager->readTextLine(serverData))
	{
		clearLastError();
		m_errorBuffer << "Failed to read configuration from: " << SERVER_INFO;
		return false;
	}
	_configManager->closeFile();

	// Parse server address and port from "address:port" format
	StringUtility::trim(serverData);
	const auto separatorPos = serverData.find(':');
	if (separatorPos == std::string::npos)
	{
		clearLastError();
		m_errorBuffer << "Invalid format in " << SERVER_INFO << ": missing ':' separator";
		return false;
	}
	const auto serverAddress = serverData.substr(0, separatorPos);
	const auto serverPort = serverData.substr(separatorPos + 1);

	// Configure network connection with parsed address and port
	if (!_networkManager->configureEndpoint(serverAddress, serverPort))
	{
		clearLastError();
		m_errorBuffer << "Invalid IP address or port in " << SERVER_INFO;
		return false;
	}
	return true;
}

/**
 * @brief Loads user credentials and cryptographic keys from configuration file
 * @return true if credentials loaded successfully, false otherwise
 * @details Reads username, UUID, and private key from my.info file and initializes
 *          the RSA cryptographic engine for secure communication
 */
bool MessageEngine::loadUserCredentials()
{
	std::string data;
	
	// Open client configuration file for reading
	if (!_configManager->openFile(CLIENT_INFO))
	{
		clearLastError();
		m_errorBuffer << "Failed to open client configuration: " << CLIENT_INFO;
		return false;
	}

	// Extract and validate username
	if (!_configManager->readTextLine(data))
	{
		clearLastError();
		m_errorBuffer << "Failed to read username from " << CLIENT_INFO;
		return false;
	}

	StringUtility::trim(data);
	if (data.length() >= CLIENT_NAME_MAX_LENGTH)
	{
		clearLastError();
		m_errorBuffer << "Username exceeds maximum allowed length";
		return false;
	}
	m_localUser.username = data;

	// Extract and validate client UUID
	if (!_configManager->readTextLine(data))
	{
		clearLastError();
		m_errorBuffer << "Failed to read client UUID from " << CLIENT_INFO;
		return false;
	}

	// Decode hex-encoded UUID to binary format
	data = StringUtility::unhex(data);
	const char* decodedUuid = data.c_str();
	if (strlen(decodedUuid) != sizeof(m_localUser.id.uuid))
	{
		memset(m_localUser.id.uuid, 0, sizeof(m_localUser.id.uuid));
		clearLastError();
		m_errorBuffer << "Invalid UUID format in " << CLIENT_INFO;
		return false;
	}
	memcpy(m_localUser.id.uuid, decodedUuid, sizeof(m_localUser.id.uuid));

	// Extract and validate private key (Base64 encoded)
	std::string privateKey;
	while (_configManager->readTextLine(data))
	{
		privateKey.append(StringUtility::decodeBase64(data));
	}

	if (privateKey.empty())
	{
		clearLastError();
		m_errorBuffer << "No private key found in " << CLIENT_INFO;
		return false;
	}
	
	// Initialize RSA cryptographic engine with private key
	try
	{
		delete _cryptoEngine;
		_cryptoEngine = new RSAPrivateWrapper(privateKey);
	}
	catch (...)
	{
		clearLastError();
		m_errorBuffer << "Failed to parse private key from " << CLIENT_INFO;
		return false;
	}

	_configManager->closeFile();
	return true;
}

/**
 * @brief Retrieves sorted list of all registered usernames
 * @return Vector of usernames sorted alphabetically
 * @details Extracts usernames from the local peer registry and sorts them
 *          for consistent display in the user interface
 */
std::vector<std::string> MessageEngine::getUsernames() const
{
	std::vector<std::string> usernames(m_peerRegistry.size());
	
	// Extract usernames from peer registry
	std::transform(m_peerRegistry.begin(), m_peerRegistry.end(), usernames.begin(),
		[](const ClientInfo& client) { return client.username; });
	
	// Sort alphabetically for consistent display
	std::sort(usernames.begin(), usernames.end());
	return usernames;
}

/**
 * @brief Clears the error message buffer and resets formatting
 * @details Resets the internal string stream to empty state and clears
 *          all error flags for fresh error reporting
 */
void MessageEngine::clearLastError()
{
	const std::stringstream clean;
	m_errorBuffer.str("");
	m_errorBuffer.clear();
	m_errorBuffer.copyfmt(clean);
}

/**
 * @brief Stores current client information to configuration file
 * @return true if storage successful, false otherwise
 * @details Writes username, UUID, and private key to my.info file for persistence
 *          and future client sessions
 */
bool MessageEngine::storeClientInfo()
{
	// Open client configuration file for writing
	if (!_configManager->openFile(CLIENT_INFO, true))
	{
		clearLastError();
		m_errorBuffer << "Failed to open " << CLIENT_INFO << " for writing";
		return false;
	}

	// Write username as first line
	if (!_configManager->writeTextLine(m_localUser.username))
	{
		clearLastError();
		m_errorBuffer << "Failed to write username to " << CLIENT_INFO;
		return false;
	}

	// Write UUID in hex format
	const auto hexUUID = StringUtility::hex(m_localUser.id.uuid, sizeof(m_localUser.id.uuid));
	if (!_configManager->writeTextLine(hexUUID))
	{
		clearLastError();
		m_errorBuffer << "Failed to write UUID to " << CLIENT_INFO;
		return false;
	}

	// Write private key in Base64 encoded format
	const auto encodedKey = StringUtility::encodeBase64(_cryptoEngine->getPrivateKey());
	if (!_configManager->writeBytes(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
	{
		clearLastError();
		m_errorBuffer << "Failed to write private key to " << CLIENT_INFO;
		return false;
	}

	_configManager->closeFile();
	return true;
}

/**
 * @brief Validates response header against expected response code
 * @param[in] header Response header to validate
 * @param[in] expectedCode Expected response code for this operation
 * @return true if header is valid, false otherwise
 * @details Checks protocol version, response code, and payload size for consistency
 *          with the expected response structure
 */
bool MessageEngine::validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode)
{
	// Check for server error response
	if (header.code == RESPONSE_ERROR)
	{
		clearLastError();
		m_errorBuffer << "Server returned error response code";
		return false;
	}

	// Verify response code matches expected code
	if (header.code != expectedCode)
	{
		clearLastError();
		m_errorBuffer << "Unexpected response code: " << header.code << " (expected: " << expectedCode << ")";
		return false;
	}

	// Validate payload size based on response type
	csize_t expectedSize = DEFAULT_VALUE;
	switch (header.code)
	{
	case RESPONSE_REGISTRATION:
	{
		expectedSize = sizeof(ResponseRegistrationStruct) - sizeof(ResponseHeaderStruct);
		break;
	}
	case RESPONSE_PUBLIC_KEY:
	{
		expectedSize = sizeof(ResponsePublicKeyStruct) - sizeof(ResponseHeaderStruct);
		break;
	}
	case RESPONSE_MSG_SENT:
	{
		expectedSize = sizeof(ResponseMessageSentStruct) - sizeof(ResponseHeaderStruct);
		break;
	}
	default:
	{
		return true; // Variable size responses are handled separately
	}
	}

	// Verify payload size matches expected size
	if (header.payloadSize != expectedSize)
	{
		clearLastError();
		m_errorBuffer << "Invalid payload size: " << header.payloadSize << " (expected: " << expectedSize << ")";
		return false;
	}

	return true;
}

/**
 * @brief Handles reception of unknown payload size with memory allocation
 * @param[in] request Pointer to request data to send
 * @param[in] reqSize Size of request data in bytes
 * @param[in] expectedCode Expected response code for validation
 * @param[out] payload Reference to payload pointer (allocated by function)
 * @param[out] size Reference to payload size in bytes
 * @return true if payload received successfully, false otherwise
 * @details Establishes connection, sends request, receives response header,
 *          validates response, and allocates memory for complete payload reception.
 *          Caller is responsible for deleting the allocated payload memory.
 */
bool MessageEngine::receiveUnknownPayload(
	const uint8_t* const request,
	const size_t reqSize,
	const ResponseCodeEnum expectedCode,
	uint8_t*& payload,
	size_t& size
) {
	ResponseHeaderStruct response;
	uint8_t buffer[DEFAULT_PACKET_SIZE];
	payload = nullptr;
	size = 0;

	// Validate input parameters
	if (request == nullptr || reqSize == 0) {
		clearLastError();
		m_errorBuffer << "Invalid request parameters";
		return false;
	}

	// Establish network connection
	if (!_networkManager->establishConnection()) {
		clearLastError();
		m_errorBuffer << "Connection failed: " << _networkManager;
		return false;
	}

	// Send request to server
	if (!_networkManager->sendData(request, reqSize)) {
		_networkManager->disconnectSocket();
		clearLastError();
		m_errorBuffer << "Failed to send request: " << _networkManager;
		return false;
	}

	// Receive response header
	if (!_networkManager->receiveData(buffer, sizeof(buffer))) {
		clearLastError();
		m_errorBuffer << "Failed to receive response header: " << _networkManager;
		return false;
	}

	// Parse and validate response header
	memcpy(&response, buffer, sizeof(ResponseHeaderStruct));
	if (!validateHeader(response, expectedCode)) {
		clearLastError();
		m_errorBuffer << "Invalid response from server: " << _networkManager;
		return false;
	}

	// Handle empty payload case
	if (response.payloadSize == 0) {
		return true;  // No payload, but successful response
	}

	// Allocate memory for complete payload
	size = response.payloadSize;
	payload = new uint8_t[size];

	// Copy initial payload chunk from buffer
	uint8_t* ptr = static_cast<uint8_t*>(buffer) + sizeof(ResponseHeaderStruct);
	size_t receivedSize = sizeof(buffer) - sizeof(ResponseHeaderStruct);
	if (receivedSize > size) {
		receivedSize = size;
	}
	memcpy(payload, ptr, receivedSize);

	// Receive remaining payload in chunks if needed
	ptr = payload + receivedSize;
	while (receivedSize < size) {
		size_t bytesToRead = (size - receivedSize);
		if (bytesToRead > DEFAULT_PACKET_SIZE) {
			bytesToRead = DEFAULT_PACKET_SIZE;
		}

		if (!_networkManager->receiveData(buffer, bytesToRead)) {
			clearLastError();
			m_errorBuffer << "Failed to receive payload data: " << _networkManager;
			delete[] payload;
			payload = nullptr;
			size = 0;
			return false;
		}

		memcpy(ptr, buffer, bytesToRead);
		receivedSize += bytesToRead;
		ptr += bytesToRead;
	}

	return true;
}

/**
 * @brief Sets public key for a specific client in peer registry
 * @param[in] clientID Target client's UUID
 * @param[in] publicKey RSA public key to store
 * @return true if key stored successfully, false otherwise
 * @details Updates the peer registry with the client's public key and sets
 *          the publicKeySet flag to true for future secure communication
 */
bool MessageEngine::setClientPublicKey(const ClientIdStruct& clientID, const PublicKeyStruct& publicKey)
{
	// Search for client in peer registry
	for (ClientInfo& client : m_peerRegistry)
	{
		if (client.id == clientID)
		{
			// Update client's public key and set flag
			client.publicKey = publicKey;
			client.publicKeySet = true;
			return true;
		}
	}
	return false; // Client not found in registry
}

/**
 * @brief Sets symmetric key for a specific client in peer registry
 * @param[in] clientID Target client's UUID
 * @param[in] symmetricKey AES symmetric key to store
 * @return true if key stored successfully, false otherwise
 * @details Updates the peer registry with the client's symmetric key and sets
 *          the symmetricKeySet flag to true for session encryption
 */
bool MessageEngine::setClientSymmetricKey(const ClientIdStruct& clientID, const SymmetricKeyStruct& symmetricKey)
{
	// Search for client in peer registry
	for (ClientInfo& client : m_peerRegistry)
	{
		if (client.id == clientID)
		{
			// Update client's symmetric key and set flag
			client.symmetricKey = symmetricKey;
			client.symmetricKeySet = true;
			return true;
		}
	}
	return false; // Client not found in registry
}

/**
 * @brief Finds client information by UUID in peer registry
 * @param[in] clientID UUID to search for
 * @param[out] client Reference to store found client information
 * @return true if client found, false otherwise
 * @details Searches the peer registry for a client with matching UUID
 *          and populates the client reference if found
 */
bool MessageEngine::findClientById(const ClientIdStruct& clientID, ClientInfo& client) const
{
	// Linear search through peer registry
	for (const ClientInfo& peer : m_peerRegistry)
	{
		if (peer.id == clientID)
		{
			client = peer;
			return true;
		}
	}
	return false; // Client not found
}

/**
 * @brief Finds client information by username in peer registry
 * @param[in] username Username to search for
 * @param[out] client Reference to store found client information
 * @return true if client found, false otherwise
 * @details Searches the peer registry for a client with matching username
 *          and populates the client reference if found
 */
bool MessageEngine::findClientByUsername(const std::string& username, ClientInfo& client) const
{
	// Linear search through peer registry
	for (const ClientInfo& peer : m_peerRegistry)
	{
		if (peer.username == username)
		{
			client = peer;
			return true;
		}
	}
	return false; // Client not found
}

/**
 * @brief Registers a new client with the server
 * @param[in] username Display name for the new client
 * @return true if registration successful, false otherwise
 * @details Sends registration request to server with username and public key,
 *          receives assigned client ID and stores it locally
 */
bool MessageEngine::registerClient(const std::string& username)
{
	// Validate username length
	if (username.length() >= CLIENT_NAME_MAX_LENGTH)
	{
		clearLastError();
		m_errorBuffer << "Username exceeds maximum allowed length";
		return false;
	}

	// Prepare registration request
	RequestRegistrationStruct request;
	memcpy(request.payload.clientName.name, username.c_str(), username.length());
	request.payload.clientName.name[username.length()] = '\0';
	
	// Get public key from RSA engine
	const std::string publicKeyStr = _cryptoEngine->getPublicKey();
	memcpy(request.payload.clientPublicKey.publicKey, publicKeyStr.c_str(), PUBLIC_KEY_LENGTH);

	// Send registration request and receive response
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;
	
	if (!receiveUnknownPayload(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		RESPONSE_REGISTRATION, payload, payloadSize))
	{
		return false; // Error message set by receiveUnknownPayload
	}

	// Parse registration response
	if (payloadSize != sizeof(ClientIdStruct))
	{
		clearLastError();
		m_errorBuffer << "Invalid registration response size";
		delete[] payload;
		return false;
	}

	// Store assigned client ID
	memcpy(&m_localUser.id, payload, sizeof(ClientIdStruct));
	delete[] payload;

	// Store client information to file for persistence
	if (!storeClientInfo())
	{
		clearLastError();
		m_errorBuffer << "Failed to store client information after registration";
		return false;
	}

	return true;
}

/**
 * @brief Requests updated list of registered clients from server
 * @return true if request successful, false otherwise
 * @details Sends clients list request to server and updates local peer registry
 *          with current client information
 */
bool MessageEngine::requestClientsList()
{
	// Prepare clients list request
	RequestClientsListStruct request(m_localUser.id);

	// Send request and receive response
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;
	
	if (!receiveUnknownPayload(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		RESPONSE_USERS, payload, payloadSize))
	{
		return false; // Error message set by receiveUnknownPayload
	}

	// Clear existing peer registry
	m_peerRegistry.clear();

	// Parse client entries from payload
	const uint8_t* ptr = payload;
	size_t parsedBytes = 0;
	
	while (parsedBytes < payloadSize)
	{
		// Extract client entry structure
		struct
		{
			ClientIdStruct   clientId;
			ClientNameStruct clientName;
		}clientEntry;
		
		if (parsedBytes + sizeof(clientEntry) > payloadSize)
		{
			clearLastError();
			m_errorBuffer << "Invalid clients list response: incomplete client entry";
			delete[] payload;
			return false;
		}

		memcpy(&clientEntry, ptr, sizeof(clientEntry));
		
		// Create client info and add to registry
		ClientInfo client;
		client.id = clientEntry.clientId;
		client.username = reinterpret_cast<const char*>(clientEntry.clientName.name);
		client.publicKeySet = false;
		client.symmetricKeySet = false;
		
		m_peerRegistry.push_back(client);

		parsedBytes += sizeof(clientEntry);
		ptr += sizeof(clientEntry);
	}

	delete[] payload;
	return true;
}

/**
 * @brief Requests public key for a specific client
 * @param[in] username Target client's username
 * @return true if request successful, false otherwise
 * @details Sends public key request to server and stores the received key
 *          in the local peer registry for future secure communication
 */
bool MessageEngine::requestClientPublicKey(const std::string& username)
{
	// Find target client in registry
	ClientInfo client;
	if (!findClientByUsername(username, client))
	{
		clearLastError();
		m_errorBuffer << "User '" << username << "' not found in local registry";
		return false;
	}

	// Prepare public key request
	RequestPublicKeyStruct request(m_localUser.id);
	request.payload = client.id;

	// Send request and receive response
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;
	
	if (!receiveUnknownPayload(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		RESPONSE_PUBLIC_KEY, payload, payloadSize))
	{
		return false; // Error message set by receiveUnknownPayload
	}

	// Parse public key response
	if (payloadSize != sizeof(ClientIdStruct) + sizeof(PublicKeyStruct))
	{
		clearLastError();
		m_errorBuffer << "Invalid public key response size";
		delete[] payload;
		return false;
	}

	// Extract client ID and public key
	ClientIdStruct responseClientId;
	PublicKeyStruct responsePublicKey;
	
	memcpy(&responseClientId, payload, sizeof(ClientIdStruct));
	memcpy(&responsePublicKey, payload + sizeof(ClientIdStruct), sizeof(PublicKeyStruct));

	// Verify client ID matches request
	if (responseClientId != client.id)
	{
		clearLastError();
		m_errorBuffer << "Public key response contains unexpected client ID";
		delete[] payload;
		return false;
	}

	// Store public key in peer registry
	if (!setClientPublicKey(client.id, responsePublicKey))
	{
		clearLastError();
		m_errorBuffer << "Failed to store public key for " << username;
		delete[] payload;
		return false;
	}

	delete[] payload;
	return true;
}

/**
 * @brief Retrieves and decrypts pending messages from server
 * @param[out] messages Vector to store decrypted message data
 * @return true if retrieval successful, false otherwise
 * @details Requests pending messages from server, decrypts them using appropriate
 *          keys, and populates the messages vector with readable content
 */
bool MessageEngine::retrievePendingMessages(std::vector<MessageData>& messages)
{
	// Clear output vector
	messages.clear();

	// Prepare pending messages request
	RequestMessagesStruct request(m_localUser.id);

	// Send request and receive response
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;
	
	if (!receiveUnknownPayload(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		RESPONSE_PENDING_MSG, payload, payloadSize))
	{
		return false; // Error message set by receiveUnknownPayload
	}

	// Handle empty response (no pending messages)
	if (payloadSize == 0)
	{
		delete[] payload;
		return true;
	}

	// Parse pending messages from payload
	const uint8_t* ptr = payload;
	size_t parsedBytes = 0;
	
	while (parsedBytes < payloadSize)
	{
		// Extract pending message header
		PendingMessageStruct* header = reinterpret_cast<PendingMessageStruct*>(const_cast<uint8_t*>(ptr));
		
		if (parsedBytes + sizeof(PendingMessageStruct) > payloadSize)
		{
			clearLastError();
			m_errorBuffer << "Invalid pending messages response: incomplete header";
			delete[] payload;
			return false;
		}

		// Validate message size
		if (parsedBytes + sizeof(PendingMessageStruct) + header->messageSize > payloadSize)
		{
			clearLastError();
			m_errorBuffer << "Invalid pending messages response: message content exceeds payload";
			delete[] payload;
			return false;
		}

		// Find source client information
		ClientInfo sourceClient;
		if (!findClientById(header->clientId, sourceClient))
		{
			clearLastError();
			m_errorBuffer << "Unknown source client for message #" << header->messageId;
			delete[] payload;
			return false;
		}

		// Create message data structure
		MessageData message;
		message.username = sourceClient.username;
		message.content = "";

		// Process message content based on type
		bool addToQueue = true;
		ptr += sizeof(PendingMessageStruct);
		parsedBytes += sizeof(PendingMessageStruct);

		switch (header->messageType)
		{
		case MSG_SYMMETRIC_KEY_REQUEST:
		{
			// Handle symmetric key request (empty content)
			message.content = "Symmetric key request";
			break;
		}
		case MSG_SYMMETRIC_KEY_SEND:
		{
			// Handle symmetric key exchange
			if (!sourceClient.publicKeySet)
			{
				m_errorBuffer << "\tMessage #" << header->messageId << ": Public key not available" << std::endl;
				addToQueue = false;
				break;
			}

			// Decrypt symmetric key with our private key
			const std::string decryptedKey = _cryptoEngine->decrypt(ptr, header->messageSize);
			
			// Store symmetric key for future communication
			SymmetricKeyStruct symKey;
			memcpy(symKey.symmetricKey, decryptedKey.c_str(), SYMMETRIC_KEY_LENGTH);
			setClientSymmetricKey(header->clientId, symKey);
			
			message.content = "Symmetric key received";
			break;
		}
		case MSG_TEXT:
		case MSG_FILE:
		{
			// Handle text messages and file transfers
			if (!sourceClient.symmetricKeySet)
			{
				m_errorBuffer << "\tMessage #" << header->messageId << ": Symmetric key not available" << std::endl;
				addToQueue = false;
				break;
			}

			// Decrypt message content with symmetric key
			AESWrapper aes(sourceClient.symmetricKey);
			const std::string decryptedData = aes.decrypt(ptr, header->messageSize);

			if (header->messageType == MSG_FILE)
			{
				// Save file content to temporary directory
				std::stringstream filepath;
				filepath << _configManager->getTemporaryDirectory() << "\\MessageU\\" << message.username << "_" << StringUtility::getTimestamp();
				message.content = filepath.str();

				if (!_configManager->writeFileComplete(message.content, decryptedData))
				{
					m_errorBuffer << "\tMessage #" << header->messageId << ": Failed to save file" << std::endl;
					addToQueue = false;
				}
			}
			else  // Message text
			{
				message.content = decryptedData;
			}
			break;
		}
		default:
		{
			message.content = ""; // Corrupted message. Don't store.
			break;
		}
		}

		// Add message to output vector if processing was successful
		if (addToQueue) {
			messages.push_back(message);
		}

		parsedBytes += header->messageSize;
		ptr += header->messageSize;
	}

	delete[] payload;
	return true;
}

/**
 * @brief Sends encrypted message to specified user
 * @param[in] username Target recipient's username
 * @param[in] type Type of message (text, file, key exchange)
 * @param[in] data Optional message content (empty for key requests)
 * @return true if message sent successfully, false otherwise
 * @details Handles complete message encryption, transmission, and confirmation
 *          including automatic key exchange if necessary
 */
bool MessageEngine::sendMessage(const std::string& username, const MessageTypeEnum type, const std::string& data)
{
	ClientInfo              client; // client to send to
	RequestSendMessageStruct  request(m_localUser.id, (type));
	ResponseMessageSentStruct response;
	uint8_t* content = nullptr;

	// Message type names for error reporting
	std::map<const MessageTypeEnum, const std::string> messageTypeNames = {
		{MSG_SYMMETRIC_KEY_REQUEST, "symmetric key request"},
		{MSG_SYMMETRIC_KEY_SEND,    "symmetric key"},
		{MSG_TEXT,                  "text message"},
		{MSG_FILE,                  "file"}
	};

	// Validate recipient (prevent self-messaging)
	if (username == m_localUser.username)
	{
		clearLastError();
		m_errorBuffer << "Cannot send " << messageTypeNames.at(type) << " to yourself";
		return false;
	}

	// Find target client in registry
	if (!findClientByUsername(username, client))
	{
		clearLastError();
		m_errorBuffer << "User '" << username << "' not found. Please refresh the user list.";
		return false;
	}
	request.payloadHeader.clientId = client.id;

	// Handle symmetric key exchange
	if (type == MSG_SYMMETRIC_KEY_SEND)
	{
		// Verify public key is available
		if (!client.publicKeySet)
		{
			clearLastError();
			m_errorBuffer << "Public key for " << client.username << " not available";
			return false;
		}

		// Generate new symmetric key for this session
		AESWrapper    aes;
		SymmetricKeyStruct symKey;
		symKey = aes.getKey();

		// Store symmetric key locally
		if (!setClientSymmetricKey(request.payloadHeader.clientId, symKey))
		{
			clearLastError();
			m_errorBuffer << "Failed to store symmetric key for " << client.username;
			return false;
		}

		// Encrypt symmetric key with recipient's public key
		RSAPublicWrapper rsa(client.publicKey);
		const std::string encryptedKey = rsa.encrypt(symKey.symmetricKey, sizeof(symKey.symmetricKey));

		// Validate size for transmission
		if (encryptedKey.size() > std::numeric_limits<csize_t>::max()) {
			clearLastError();
			m_errorBuffer << "Encrypted key exceeds maximum transmission size";
			return false;
		}

		request.payloadHeader.contentSize = static_cast<csize_t>(encryptedKey.size());
		content = new uint8_t[request.payloadHeader.contentSize];
		memcpy(content, encryptedKey.c_str(), request.payloadHeader.contentSize);
	}
	else if (type == MSG_TEXT || type == MSG_FILE)
	{
		// Handle text messages and file transfers
		if (data.empty())
		{
			clearLastError();
			m_errorBuffer << "No content provided for message";
			return false;
		}
		
		// Verify symmetric key is available
		if (!client.symmetricKeySet)
		{
			clearLastError();
			m_errorBuffer << "Symmetric key for " << client.username << " not available";
			return false;
		}

		uint8_t* fileData = nullptr;
		size_t fileSize = 0;

		// For files, read the content from disk
		if ((type == MSG_FILE) && !_configManager->readFileComplete(data, fileData, fileSize))
		{
			clearLastError();
			m_errorBuffer << "File not found: " << data;
			return false;
		}

		// Encrypt content with symmetric key
		AESWrapper aes(client.symmetricKey);
		const std::string encrypted = (type == MSG_TEXT) 
			? aes.encrypt(data) 
			: aes.encrypt(fileData, fileSize);

		// Clean up file data if needed
		delete[] fileData;

		// Validate size for transmission
		if (encrypted.size() > std::numeric_limits<csize_t>::max()) {
			clearLastError();
			m_errorBuffer << "Encrypted content exceeds maximum transmission size";
			return false;
		}

		request.payloadHeader.contentSize = static_cast<csize_t>(encrypted.size());
		content = new uint8_t[request.payloadHeader.contentSize];
		memcpy(content, encrypted.c_str(), request.payloadHeader.contentSize);
	}

	// Prepare complete message packet
	size_t msgSize;
	uint8_t* msgPacket;
	request.header.payloadSize = sizeof(request.payloadHeader) + request.payloadHeader.contentSize;

	if (content == nullptr)
	{
		// No content (e.g., symmetric key request)
		msgPacket = reinterpret_cast<uint8_t*>(&request);
		msgSize = sizeof(request);
	}
	else
	{
		// Allocate memory for request + content
		msgPacket = new uint8_t[sizeof(request) + request.payloadHeader.contentSize];
		memcpy(msgPacket, &request, sizeof(request));
		memcpy(msgPacket + sizeof(request), content, request.payloadHeader.contentSize);
		msgSize = sizeof(request) + request.payloadHeader.contentSize;
	}

	// Send message and receive confirmation
	bool success = _networkManager->exchangeData(msgPacket, msgSize, reinterpret_cast<uint8_t* const>(&response), sizeof(response));

	// Clean up resources
	delete[] content;
	if (msgPacket != reinterpret_cast<uint8_t*>(&request)) {
		delete[] msgPacket;
	}

	if (!success) {
		clearLastError();
		m_errorBuffer << "Communication with server failed: " << _networkManager;
		return false;
	}

	// Validate response header
	if (!validateHeader(response.header, RESPONSE_MSG_SENT))
		return false;  // Error message set by validateHeader

	// Verify response contains correct client ID
	if (request.payloadHeader.clientId != response.payload.clientId)
	{
		clearLastError();
		m_errorBuffer << "Unexpected clientID was received.";
		return false;
	}
	return true;
}

