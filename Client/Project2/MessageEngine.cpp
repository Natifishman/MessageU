/**
 * @author		Natanel Maor Fishman
 * @file		MessageEngine.cpp
 * @brief       Client's primary message processing and coordination component.
 * @note        MessageEngine orchestrates communication between the console interface
 *              and backend subsystems including configuration management and network communication layers.
 */
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "MessageEngine.h"
#include "StringUtility.h"
#include "ConfigManager.h"
#include "NetworkConnection.h"
#include <limits>


 //Stream operator for MessageType enumeration
std::ostream& operator<<(std::ostream& os, const MessageTypeEnum& type)
{
	// Cast enumeration to underlying type for serialization
	os << static_cast<messageType_t>(type);
	return os;
}

//Constructs a new MessageEngine with initialized subsystems
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

MessageEngine::~MessageEngine() {
	cleanup();
}

void MessageEngine::cleanup() {
	// Release resources in optimal order
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

// Parses server connection information from configuration file
bool MessageEngine::loadServerConfiguration()
{
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

	// Parse server address and port
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

	if (!_networkManager->configureEndpoint(serverAddress, serverPort))
	{
		clearLastError();
		m_errorBuffer << "Invalid IP address or port in " << SERVER_INFO;
		return false;
	}
	return true;
}


bool MessageEngine::loadUserCredentials()
{
	std::string data;
	if (!_configManager->openFile(CLIENT_INFO))
	{
		clearLastError();
		m_errorBuffer << "Failed to open client configuration: " << CLIENT_INFO;
		return false;
	}

	// Extract username
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

	// Extract client UUID
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

	// Extract private key
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
 * Copy usernames into vector & sort them alphabetically.
 * If m_peerRegistry is empty, an empty vector will be returned.
 */
std::vector<std::string> MessageEngine::getUsernames() const
{
	std::vector<std::string> usernames(m_peerRegistry.size());
	std::transform(m_peerRegistry.begin(), m_peerRegistry.end(), usernames.begin(),
		[](const ClientInfo& client) { return client.username; });
	std::sort(usernames.begin(), usernames.end());
	return usernames;
}

/**
 * Reset m_errorBuffer StringStream: Empty string, clear errors flag and reset formatting.
 */
void MessageEngine::clearLastError()
{
	const std::stringstream clean;
	m_errorBuffer.str("");
	m_errorBuffer.clear();
	m_errorBuffer.copyfmt(clean);
}

/**
 * Store client info to CLIENT_INFO file.
 */
bool MessageEngine::storeClientInfo()
{
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

	// Write UUID.
	const auto hexUUID = StringUtility::hex(m_localUser.id.uuid, sizeof(m_localUser.id.uuid));
	if (!_configManager->writeTextLine(hexUUID))
	{
		clearLastError();
		m_errorBuffer << "Failed to write UUID to " << CLIENT_INFO;
		return false;
	}

	// Write private key (Base64 encoded)
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
 * Validate ResponseHeaderStruct upon an expected ResponseCodeEnum.
 */
bool MessageEngine::validateHeader(const ResponseHeaderStruct& header, const ResponseCodeEnum expectedCode)
{
	if (header.code == RESPONSE_ERROR)
	{
		clearLastError();
		m_errorBuffer << "Server returned error response code";
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
 * Receive unknown payload. Payload size is parsed from header.
 * Caller responsible for deleting payload upon success.
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

/**
 * Store a client's public key on RAM.
 */
bool MessageEngine::setClientPublicKey(const ClientIdStruct& clientID, const PublicKeyStruct& publicKey)
{
	for (ClientInfo& client : m_peerRegistry)
	{
		if (client.id == clientID)
		{
			client.publicKey = publicKey;
			client.publicKeySet = true;
			return true;
		}
	}
	return false;
}

/**
 * Store a client's symmetric key on RAM.
 */
bool MessageEngine::setClientSymmetricKey(const ClientIdStruct& clientID, const SymmetricKeyStruct& symmetricKey)
{
	for (ClientInfo& client : m_peerRegistry)
	{
		if (client.id == clientID)
		{
			client.symmetricKey = symmetricKey;
			client.symmetricKeySet = true;
			return true;
		}
	}
	return false;
}


/**
 * Find a client using client ID.
 * Clients list must be retrieved first.
 */
bool MessageEngine::findClientById(const ClientIdStruct& clientID, ClientInfo& client) const
{
	for (const ClientInfo& entry : m_peerRegistry)
	{
		if (entry.id == clientID)
		{
			client = entry;
			return true;
		}
	}
	return false;
}

/**
 * Find a client using username.
 * Clients list must be retrieved first.
 */
bool MessageEngine::findClientByUsername(const std::string& username, ClientInfo& client) const
{
	for (const ClientInfo& entry : m_peerRegistry)
	{
		if (username == entry.username)
		{
			client = entry;
			return true;
		}
	}
	return false; // client invalid.
}

/**
 * Register client via the server.
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

	for (auto ch : username)
	{
		if (!std::isalnum(ch))  // check alphanumeric
		{
			clearLastError();
			m_errorBuffer << "Username must contain only letters and numbers";
			return false;
		}
	}

	// Generate new RSA key pair
	delete _cryptoEngine;
	_cryptoEngine = new RSAPrivateWrapper();
	const auto publicKey = _cryptoEngine->getPublicKey();

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
 * Invoke logic: request client list from server.
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
	m_peerRegistry.clear();

	while (parsedBytes < payloadSize)
	{
		memcpy(&clientEntry, ptr, sizeof(clientEntry));
		ptr += sizeof(clientEntry);
		parsedBytes += sizeof(clientEntry);

		// Ensure null termination of client name
		clientEntry.clientName.name[sizeof(clientEntry.clientName.name) - 1] = '\0';

		m_peerRegistry.push_back({ clientEntry.clientId, reinterpret_cast<char*>(clientEntry.clientName.name) });
	}
	delete[] payload;
	return true;
}


/**
 * Invoke logic: request client public key from server.
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

	if (!findClientByUsername(username, client))
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
	if (!setClientPublicKey(response.payload.clientId, response.payload.clientPublicKey))
	{
		clearLastError();
		m_errorBuffer << "Failed to store public key for " << username << ". Please refresh user list.";
		return false;
	}
	return true;
}


/**
 * Invoke logic: request pending messages from server.
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
		if (findClientById(header->clientId, client))
		{
			message.username = client.username;
		}
		else
		{
			// Handle unknown client ID
			message.username = "Unknown client: ";
			message.username.append(StringUtility::hex(header->clientId.uuid, sizeof(header->clientId.uuid)));
		}

		ptr += msgHeaderSize;
		parsedBytes += msgHeaderSize;

		// Process message based on type
		switch (header->messageType)
		{
		case MSG_SYMMETRIC_KEY_REQUEST:
		{
			message.content = "Request for symmetric key";
			messages.push_back(message);
			break;
		}

		case MSG_SYMMETRIC_KEY_SEND:
		{
			if (header->messageSize == 0)
			{
				m_errorBuffer << "\tMessage #" << header->messageId << ": Invalid symmetric key (empty content)" << std::endl;
				parsedBytes += header->messageSize;
				ptr += header->messageSize;
				continue;
			}

			std::string key;
			try
			{
				key = _cryptoEngine->decrypt(ptr, header->messageSize);
			}
			catch (...)
			{

				m_errorBuffer << "\tMessage #" << header->messageId << ": Failed to decrypt symmetric key" << std::endl;
				parsedBytes += header->messageSize;
				ptr += header->messageSize;
				continue;
			}

			const size_t keySize = key.size();
			if (keySize != SYMMETRIC_KEY_LENGTH)  // invalid symmetric key
			{
				m_errorBuffer << "\tMessage #" << header->messageId << ": Invalid symmetric key length (" << key.size() << ")" << std::endl;
			}
			else
			{
				memcpy(client.symmetricKey.symmetricKey, key.c_str(), keySize);
				if (setClientSymmetricKey(header->clientId, client.symmetricKey))
				{
					message.content = "Symmetric key received";
					messages.push_back(message);
				}
				else
				{
					m_errorBuffer << "\tMessage #" << header->messageId << ": Failed to store symmetric key for " << message.username << std::endl;
				}
			}
			parsedBytes += header->messageSize;
			ptr += header->messageSize;
			break;
		}

		case MSG_TEXT:
		case MSG_FILE:
		{
			if (header->messageSize == 0)
			{
				m_errorBuffer << "\tMessage #" << header->messageId << ": Empty message content" << std::endl;
				parsedBytes += header->messageSize;
				ptr += header->messageSize;
				continue;
			}

			message.content = "Cannot decrypt message"; // Default error message
			bool addToQueue = true;

			if (client.symmetricKeySet)
			{
				AESWrapper aes(client.symmetricKey);
				std::string decryptedData;

				try
				{
					decryptedData = aes.decrypt(ptr, header->messageSize);
				}
				catch (...) {} // Keep default error message

				if (header->messageType == MSG_FILE)
				{
					// Set filename with timestamp.
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
			}

			if (addToQueue) {
				messages.push_back(message);
			}

			parsedBytes += header->messageSize;
			ptr += header->messageSize;
			break;
		}
		default:
		{
			message.content = ""; // Corrupted message. Don't store.
			break;
		}
		}

	}

	delete[] payload;
	return true;
}


// Send a message to another client via the server.
bool MessageEngine::sendMessage(const std::string& username, const MessageTypeEnum type, const std::string& data)
{
	ClientInfo              client; // client to send to
	RequestSendMessageStruct  request(m_localUser.id, (type));
	ResponseMessageSentStruct response;
	uint8_t* content = nullptr;

	std::map<const MessageTypeEnum, const std::string> messageTypeNames = {
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

	if (!findClientByUsername(username, client))
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

		// Generate and store symmetric key
		AESWrapper    aes;
		SymmetricKeyStruct symKey;
		symKey = aes.getKey();

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

		// Encrypt content
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

