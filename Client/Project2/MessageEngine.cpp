/**
 * @file        MessageEngine.cpp
 * @author      Natanel Maor Fishman
 * @brief       Client's primary message processing and coordination component.
 * @details     Orchestrates communication between the console interface and backend subsystems including configuration management and network communication layers.
 * @date        2025
 */
 // ================================
 // Includes and Constants
 // ================================
#include "MessageEngine.h"
#include "StringUtility.h"
#include "ConfigManager.h"
#include "NetworkConnection.h"
#include "CryptoManager.h"
#include "MessageProcessor.h"
#include "ClientRegistry.h"
#include <map>
#include <limits>
#include <limits>

// ================================
// Stream Operators
// ================================
/**
 * @brief       Stream operator for MessageType enumeration.
 * @param[out]  os      Output stream.
 * @param[in]   type    Message type enumeration value.
 * @return      Reference to the output stream.
 * @details     Casts enumeration to underlying type for serialization.
 */
std::ostream& operator<<(std::ostream& os, const MessageTypeEnum& type)
{
	// Serialize MessageTypeEnum as its underlying integer type for protocol transmission
	os << static_cast<messageType_t>(type);
	return os;
}

// ================================
// Constructor and Destructor
// ================================
/**
 * @brief       Constructs a new MessageEngine with initialized subsystems.
 * @details     Initializes configuration manager and network connection. Handles allocation failures and resource cleanup.
 */
MessageEngine::MessageEngine() : _configManager(nullptr), _networkManager(nullptr), 
	_cryptoManager(nullptr), _messageProcessor(nullptr), _clientRegistry(nullptr)
{
	try {
		// Allocate core subsystems. Throws std::bad_alloc on failure.
		_configManager = new ConfigManager();
		_networkManager = new NetworkConnection();
		_cryptoManager = new CryptoManager();
		_clientRegistry = new ClientRegistry();
		_messageProcessor = new MessageProcessor(_cryptoManager, _configManager);
	}
	catch (const std::bad_alloc& e) {
		// Defensive: Clean up partial state and propagate error
		clearLastError();
		m_errorBuffer << "Failed to initialize MessageEngine: " << e.what();
		cleanup();
		throw;
	}
}

/**
 * @brief       Destructor. Cleans up all allocated resources.
 */
MessageEngine::~MessageEngine() {
	// Always release all owned resources
	cleanup();
}

// ================================
// Public Interface Methods
// ================================

/**
 * @brief       Parses server connection information from configuration file.
 * @return      true if configuration loaded successfully, false otherwise.
 * @details     Reads server address and port from SERVER_INFO file and configures network endpoint.
 */
bool MessageEngine::loadServerConfiguration()
{
	// Open and parse server info file (address:port)
	if (!_configManager->openFile(SERVER_INFO))
	{
		clearLastError();
		m_errorBuffer << "Failed to open server configuration file: " << SERVER_INFO;
		return false;
	}

	std::string serverData;
	if (!_configManager->readTextLine(serverData))
	{
		clearLastError();
		m_errorBuffer << "Failed to read configuration from: " << SERVER_INFO;
		return false;
	}
	_configManager->closeFile();

	// Defensive: Validate format (must contain ':')
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

	// Validate and store endpoint
	if (!_networkManager->configureEndpoint(serverAddress, serverPort))
	{
		clearLastError();
		m_errorBuffer << "Invalid IP address or port in " << SERVER_INFO;
		return false;
	}
	return true;
}

/**
 * @brief       Loads user credentials from configuration file.
 * @return      true if credentials loaded successfully, false otherwise.
 * @details     Reads username, UUID, and private key from CLIENT_INFO file and initializes cryptographic engine.
 */
bool MessageEngine::loadUserCredentials()
{
	std::string data;
	if (!_configManager->openFile(CLIENT_INFO))
	{
		clearLastError();
		m_errorBuffer << "Failed to open client configuration: " << CLIENT_INFO;
		return false;
	}

	// Username (first line)
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

	// UUID (second line, hex encoded)
	if (!_configManager->readTextLine(data))
	{
		clearLastError();
		m_errorBuffer << "Failed to read client UUID from " << CLIENT_INFO;
		return false;
	}
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

	// Private key (Base64, may span multiple lines)
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
	if (!_cryptoManager->loadRSAPrivateKey(privateKey))
	{
		clearLastError();
		m_errorBuffer << "Failed to parse private key from " << CLIENT_INFO;
		return false;
	}

	_configManager->closeFile();
	return true;
}

/**
 * @brief       Registers a client via the server.
 * @param[in]   username   The username to register.
 * @return      true if registration succeeded, false otherwise.
 * @details     Generates a new RSA key pair and sends registration request to the server.
 */
bool MessageEngine::registerClient(const std::string& username)
{
	RequestRegistrationStruct  request;
	ResponseRegistrationStruct response;

	if (username.length() >= CLIENT_NAME_MAX_LENGTH)  // >= because of null termination.
	{
		clearLastError();
		m_errorBuffer << "Username too long (max " << (CLIENT_NAME_MAX_LENGTH - 1) << " characters)";
		return false;
	}

	// Validate username contains only printable ASCII characters (space to tilde: 32-126)
	for (auto ch : username)
	{
		if (ch < 32 || ch > 126)  // check printable ASCII range
		{
			clearLastError();
			m_errorBuffer << "Username must contain only printable ASCII characters";
			return false;
		}
	}

	// Generate new RSA key pair
	if (!_cryptoManager->generateRSAKeyPair())
	{
		clearLastError();
		m_errorBuffer << "Failed to generate RSA key pair";
		return false;
	}

	const auto publicKey = _cryptoManager->getRSAPublicKey();
	if (publicKey.size() != PUBLIC_KEY_LENGTH)
	{
		clearLastError();
		m_errorBuffer << "Generated public key has invalid length";
		return false;
	}

	// Prepare registration request
	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_MAX_LENGTH, username.c_str());
	memcpy(request.payload.clientPublicKey.publicKey, publicKey.c_str(), sizeof(request.payload.clientPublicKey.publicKey));

	// Send request and receive response
	if (!_networkManager->exchangeData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		m_errorBuffer << "Communication with server failed: " << _networkManager;
		return false;
	}

	// Validate response
	if (!validateHeader(response.header, RESPONSE_REGISTRATION))
		return false;	  // Error message set by validateHeader

	// Store client info
	m_localUser.id = response.payload;
	m_localUser.username = username;
	m_localUser.publicKey = request.payload.clientPublicKey;

	if (!storeClientInfo())
	{
		clearLastError();
		m_errorBuffer << "Failed to save client information. Please try registering with a different username.";
		return false;
	}

	return true;
}

/**
 * @brief       Requests the client list from the server and updates the local registry.
 * @return      true if the client list was retrieved successfully, false otherwise.
 * @details     Populates m_peerRegistry with the list of clients from the server.
 */
bool MessageEngine::requestClientsList()
{
	RequestClientsListStruct request(m_localUser.id);
	uint8_t* payload = nullptr;
	uint8_t* ptr = nullptr;
	size_t payloadSize = 0;
	size_t parsedBytes = 0;

	struct
	{
		ClientIdStruct   clientId;
		ClientNameStruct clientName;
	}clientEntry;

	if (!receiveUnknownPayload(reinterpret_cast<uint8_t*>(&request), sizeof(request), RESPONSE_USERS, payload, payloadSize))
		return false;  // Error message set by receiveUnknownPayload

	if (payloadSize == 0)
	{
		delete[] payload;
		clearLastError();
		m_errorBuffer << "No registered users found on server";
		return false;
	}

	if (payloadSize % sizeof(clientEntry) != 0)
	{
		delete[] payload;
		clearLastError();
		m_errorBuffer << "Received corrupted client list data";
		return false;
	}

	ptr = payload;
	_clientRegistry->clear();

	while (parsedBytes < payloadSize)
	{
		memcpy(&clientEntry, ptr, sizeof(clientEntry));
		ptr += sizeof(clientEntry);
		parsedBytes += sizeof(clientEntry);

		// Ensure null termination of client name
		clientEntry.clientName.name[sizeof(clientEntry.clientName.name) - 1] = '\0';

		ClientInfo client(clientEntry.clientId, reinterpret_cast<char*>(clientEntry.clientName.name));
		_clientRegistry->addClient(client);
	}
	delete[] payload;
	return true;
}

/**
 * @brief       Requests a client's public key from the server.
 * @param[in]   username   The username whose public key is requested.
 * @return      true if the public key was retrieved and stored successfully, false otherwise.
 */
bool MessageEngine::requestClientPublicKey(const std::string& username)
{
	RequestPublicKeyStruct  request(m_localUser.id);
	ResponsePublicKeyStruct response;
	ClientInfo            client;

	// Validate request
	if (username == m_localUser.username)
	{
		clearLastError();
		m_errorBuffer << "Cannot request your own public key";
		return false;
	}

	if (!_clientRegistry->findClientByUsername(username, client))
	{
		clearLastError();
		m_errorBuffer << "User '" << username << "' not found. Please refresh the user list.";
		return false;
	}

	request.payload = client.id;

	// Request public key from server
	if (!_networkManager->exchangeData(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
	{
		clearLastError();
		m_errorBuffer << "Communication with server failed: " << _networkManager;
		return false;
	}

	// Validate response
	if (!validateHeader(response.header, RESPONSE_PUBLIC_KEY))
		return false;  // error message set by validateHeader.

	if (request.payload != response.payload.clientId)
	{
		clearLastError();
		m_errorBuffer << "Server returned wrong client ID";
		return false;
	}

	// Store public key
	if (!_clientRegistry->setClientPublicKey(response.payload.clientId, response.payload.clientPublicKey))
	{
		clearLastError();
		m_errorBuffer << "Failed to store public key for " << username << ". Please refresh user list.";
		return false;
	}
	return true;
}

/**
 * @brief       Retrieves all pending messages from the server.
 * @param[out]  messages   Vector to store the retrieved messages.
 * @return      true if messages were retrieved successfully, false otherwise.
 * @details     Handles decryption and file saving for received messages.
 */
bool MessageEngine::retrievePendingMessages(std::vector<MessageData>& messages)
{
	RequestMessagesStruct  request(m_localUser.id);
	uint8_t* payload = nullptr;
	uint8_t* ptr = nullptr;
	size_t   payloadSize = 0;
	size_t   parsedBytes = 0;

	messages.clear();

	if (!receiveUnknownPayload(reinterpret_cast<uint8_t*>(&request), sizeof(request), RESPONSE_PENDING_MSG, payload, payloadSize))
		return false; // Error message set by receiveUnknownPayload

	if (payloadSize == 0)
	{
		delete[] payload;
		clearLastError();
		m_errorBuffer << "No pending messages";
		return false;
	}
	if (payload == nullptr || payloadSize < sizeof(PendingMessageStruct))
	{
		delete[] payload;
		clearLastError();
		m_errorBuffer << "Invalid response payload";
		return false;
	}

	clearLastError();
	ptr = payload;
	while (parsedBytes < payloadSize)
	{
		ClientInfo      client;
		MessageData     message;
		const size_t msgHeaderSize = sizeof(PendingMessageStruct);
		const auto   header = reinterpret_cast<PendingMessageStruct*>(ptr);
		const size_t remainingBytes = payloadSize - parsedBytes;

		// Validate message structure
		if ((msgHeaderSize > remainingBytes) || (msgHeaderSize + header->messageSize) > remainingBytes)
		{
			delete[] payload;
			clearLastError();
			m_errorBuffer << "Corrupted message data detected";
			return false;
		}

		//Resolve username
		if (!_clientRegistry->findClientById(header->clientId, client))
		{
			// Handle unknown client ID
			client.id = header->clientId;
			client.username = "Unknown client: ";
			client.username.append(StringUtility::hex(header->clientId.uuid, sizeof(header->clientId.uuid)));
			client.publicKeySet = false;
			client.symmetricKeySet = false;
		}

		ptr += msgHeaderSize;
		parsedBytes += msgHeaderSize;

		// Convert ClientInfo to MessageProcessor::ClientInfo
		MessageProcessor::ClientInfo processorClient;
		processorClient.id = client.id;
		processorClient.username = client.username;
		processorClient.publicKey = client.publicKey;
		processorClient.symmetricKey = client.symmetricKey;
		processorClient.publicKeySet = client.publicKeySet;
		processorClient.symmetricKeySet = client.symmetricKeySet;

		// Process message using MessageProcessor
		std::string errorMessage;
		MessageData processedMessage = _messageProcessor->processMessage(*header, ptr, processorClient, errorMessage);
		
		if (processedMessage.isValid) {
			// Handle symmetric key storage for MSG_SYMMETRIC_KEY_SEND
			if (header->messageType == MSG_SYMMETRIC_KEY_SEND) {
				// MessageProcessor handled the decryption, now we need to store the key
				std::string key = _cryptoManager->decryptRSA(ptr, header->messageSize);
				if (!key.empty() && key.size() == SYMMETRIC_KEY_LENGTH) {
					SymmetricKeyStruct symKey;
					memcpy(symKey.symmetricKey, key.c_str(), SYMMETRIC_KEY_LENGTH);
					_clientRegistry->setClientSymmetricKey(header->clientId, symKey);
				}
			}
			messages.push_back(processedMessage);
		} else if (!errorMessage.empty()) {
			m_errorBuffer << "\tMessage #" << header->messageId << ": " << errorMessage << std::endl;
		}

		parsedBytes += header->messageSize;
		ptr += header->messageSize;

	}

	delete[] payload;
	return true;
}

/**
 * @brief       Sends a message to another client via the server.
 * @param[in]   username   The recipient's username.
 * @param[in]   type       The type of message to send.
 * @param[in]   data       The message content or file path.
 * @return      true if the message was sent successfully, false otherwise.
 * @details     Handles encryption, key management, and file reading as needed.
 */
bool MessageEngine::sendMessage(const std::string& username, const MessageTypeEnum type, const std::string& data)
{
	ClientInfo              client; // client to send to
	RequestSendMessageStruct  request(m_localUser.id, (type));
	ResponseMessageSentStruct response;
	uint8_t* content = nullptr;

	static const std::map<MessageTypeEnum, std::string> messageTypeNames = {
		{MSG_SYMMETRIC_KEY_REQUEST, "symmetric key request"},
		{MSG_SYMMETRIC_KEY_SEND,    "symmetric key"},
		{MSG_TEXT,                  "text message"},
		{MSG_FILE,                  "file"}
	};

	// Validate recipient
	if (username == m_localUser.username)
	{
		clearLastError();
		m_errorBuffer << "Cannot send " << messageTypeNames.at(type) << " to yourself";
		return false;
	}

	if (!_clientRegistry->findClientByUsername(username, client))
	{
		clearLastError();
		m_errorBuffer << "User '" << username << "' not found. Please refresh the user list.";
		return false;
	}
	request.payloadHeader.clientId = client.id;

	if (type == MSG_SYMMETRIC_KEY_SEND)
	{
		if (!client.publicKeySet)
		{
			clearLastError();
			m_errorBuffer << "Public key for " << client.username << " not available";
			return false;
		}

		// Convert ClientInfo to MessageProcessor::ClientInfo
		MessageProcessor::ClientInfo processorClient;
		processorClient.id = client.id;
		processorClient.username = client.username;
		processorClient.publicKey = client.publicKey;
		processorClient.symmetricKey = client.symmetricKey;
		processorClient.publicKeySet = client.publicKeySet;
		processorClient.symmetricKeySet = client.symmetricKeySet;

		// Generate and store symmetric key using MessageProcessor
		std::string encryptedKey;
		SymmetricKeyStruct symKey;
		
		if (!_messageProcessor->prepareSymmetricKeyMessage(processorClient, encryptedKey, symKey))
		{
			clearLastError();
			m_errorBuffer << "Failed to prepare symmetric key for " << client.username;
			return false;
		}

		if (!_clientRegistry->setClientSymmetricKey(request.payloadHeader.clientId, symKey))
		{
			clearLastError();
			m_errorBuffer << "Failed to store symmetric key for " << client.username;
			return false;
		}


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
			// Handle text messages and file transfers using MessageProcessor
		if (data.empty())
		{
			clearLastError();
			m_errorBuffer << "No content provided for message";
			return false;
		}
		if (!client.symmetricKeySet)
		{
			clearLastError();
			m_errorBuffer << "Symmetric key for " << client.username << " not available";
			return false;
		}

		// Convert ClientInfo to MessageProcessor::ClientInfo
		MessageProcessor::ClientInfo processorClient;
		processorClient.id = client.id;
		processorClient.username = client.username;
		processorClient.publicKey = client.publicKey;
		processorClient.symmetricKey = client.symmetricKey;
		processorClient.publicKeySet = client.publicKeySet;
		processorClient.symmetricKeySet = client.symmetricKeySet;

		std::string encrypted;
		bool success = (type == MSG_TEXT) 
			? _messageProcessor->prepareTextMessage(data, processorClient, encrypted)
			: _messageProcessor->prepareFileMessage(data, processorClient, encrypted);

		if (!success)
		{
			clearLastError();
			m_errorBuffer << ((type == MSG_TEXT) ? "Failed to encrypt message" : "Failed to encrypt file: " + data);
			return false;
		}


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

	// prepare message to send
	size_t msgSize;
	uint8_t* msgPacket;
	request.header.payloadSize = sizeof(request.payloadHeader) + request.payloadHeader.contentSize;

	if (content == nullptr)
	{
		msgPacket = reinterpret_cast<uint8_t*>(&request);
		msgSize = sizeof(request);
	}
	else
	{
		msgPacket = new uint8_t[sizeof(request) + request.payloadHeader.contentSize];
		memcpy(msgPacket, &request, sizeof(request));
		memcpy(msgPacket + sizeof(request), content, request.payloadHeader.contentSize);
		msgSize = sizeof(request) + request.payloadHeader.contentSize;
	}

	// Send message and receive confirmation
	bool success = _networkManager->exchangeData(msgPacket, msgSize, reinterpret_cast<uint8_t* const>(&response), sizeof(response));

	// Clean up resources
	delete[] content;
	if (msgPacket != reinterpret_cast<uint8_t*>(&request)) { delete[] msgPacket; }

	if (!success) {
		clearLastError();
		m_errorBuffer << "Communication with server failed: " << _networkManager;
		return false;
	}

	// Validate response
	if (!validateHeader(response.header, RESPONSE_MSG_SENT))
		return false;  // Error message set by validateHeade

	if (request.payloadHeader.clientId != response.payload.clientId)
	{
		clearLastError();
		m_errorBuffer << "Unexpected clientID was received.";
		return false;
	}
	return true;
}

/**
 * @brief       Retrieves a sorted vector of all known usernames.
 * @return      Vector of usernames (alphabetically sorted).
 * @details     If m_peerRegistry is empty, returns an empty vector.
 */
std::vector<std::string> MessageEngine::getUsernames() const
{
	// Copy and sort usernames for display
	return _clientRegistry->getAllUsernames();
}

/**
 * @brief       Stores client info to CLIENT_INFO file.
 * @return      true if client info stored successfully, false otherwise.
 */
bool MessageEngine::storeClientInfo()
{
	// Open file for writing (overwrite mode)
	if (!_configManager->openFile(CLIENT_INFO, true))
	{
		clearLastError();
		m_errorBuffer << "Failed to open " << CLIENT_INFO << " for writing";
		return false;
	}

	// Write username
	if (!_configManager->writeTextLine(m_localUser.username))
	{
		clearLastError();
		m_errorBuffer << "Failed to write username to " << CLIENT_INFO;
		return false;
	}

	// Write UUID (hex encoded)
	const auto hexUUID = StringUtility::hex(m_localUser.id.uuid, sizeof(m_localUser.id.uuid));
	if (!_configManager->writeTextLine(hexUUID))
	{
		clearLastError();
		m_errorBuffer << "Failed to write UUID to " << CLIENT_INFO;
		return false;
	}

	// Write private key (Base64 encoded)
	const auto encodedKey = StringUtility::encodeBase64(_cryptoManager->getRSAPrivateKey());
	if (!_configManager->writeBytes(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
	{
		clearLastError();
		m_errorBuffer << "Failed to write private key to " << CLIENT_INFO;
		return false;
	}

	_configManager->closeFile();
	return true;
}

// ================================
// Private and Helper Methods
// ================================

/**
 * @brief       Releases all allocated subsystem resources.
 * @details     Deletes cryptographic engine, network manager, and config manager in order.
 */
void MessageEngine::cleanup() {
	// Order of deletion is important for dependency safety
	if (_messageProcessor) {
		delete _messageProcessor;
		_messageProcessor = nullptr;
	}
	if (_clientRegistry) {
		delete _clientRegistry;
		_clientRegistry = nullptr;
	}
	if (_cryptoManager) {
		delete _cryptoManager;
		_cryptoManager = nullptr;
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
 * @brief       Resets m_errorBuffer StringStream.
 * @details     Empties the string, clears error flags, and resets formatting.
 */
void MessageEngine::clearLastError()
{
	// Reset error buffer and formatting
	const std::stringstream clean;
	m_errorBuffer.str("");
	m_errorBuffer.clear();
	m_errorBuffer.copyfmt(clean);
}

/**
 * @brief       Validates a response header against an expected response code.
 * @param[in]   header         The response header to validate.
 * @param[in]   expectedCode   The expected response code.
 * @return      true if header is valid and matches expected code, false otherwise.
 * @details     Checks for error codes and validates payload size for known response types.
 */
bool MessageEngine::validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode)
{
	if (header.code == RESPONSE_ERROR)
	{
		clearLastError();
		m_errorBuffer << "server responded with an error";
		return false;
	}

	if (header.code != expectedCode)
	{
		clearLastError();
		m_errorBuffer << "Unexpected response code: " << header.code << " (expected: " << expectedCode << ")";
		return false;
	}

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
		return true;
	}
	}

	if (header.payloadSize != expectedSize)
	{
		clearLastError();
		m_errorBuffer << "Invalid payload size: " << header.payloadSize << " (expected: " << expectedSize << ")";
		return false;
	}

	return true;
}

/**
 * @brief       Receives an unknown payload from the server.
 * @param[in]   request        Pointer to the request buffer.
 * @param[in]   reqSize        Size of the request buffer.
 * @param[in]   expectedCode   Expected response code from the server.
 * @param[out]  payload        Pointer to the received payload (allocated on success, must be deleted by caller).
 * @param[out]  size           Size of the received payload.
 * @return      true if payload received successfully, false otherwise.
 * @details     Handles connection, transmission, and dynamic allocation of payload buffer.
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

	if (request == nullptr || reqSize == 0) {
		clearLastError();
		m_errorBuffer << "Invalid request parameters";
		return false;
	}

	if (!_networkManager->establishConnection()) {
		clearLastError();
		m_errorBuffer << "Connection failed: " << _networkManager;
		return false;
	}

	if (!_networkManager->sendData(request, reqSize)) {
		_networkManager->disconnectSocket();
		clearLastError();
		m_errorBuffer << "Failed to send request: " << _networkManager;
		return false;
	}

	if (!_networkManager->receiveData(buffer, sizeof(buffer))) {
		clearLastError();
		m_errorBuffer << "Failed to receive response header: " << _networkManager;
		return false;
	}

	memcpy(&response, buffer, sizeof(ResponseHeaderStruct));
	if (!validateHeader(response, expectedCode)) {
		clearLastError();
		m_errorBuffer << "Invalid response from server: " << _networkManager;
		return false;
	}

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

	// Receive remaining payload if needed
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

