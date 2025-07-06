/**
 * @author Natanel Maor Fishman
 * @file   protocol.h
 * @brief  Establishes client-server communication standards as specified in requirements.
 * @note   All data structures use 1-byte alignment through pragma pack(push, 1) directive.
 * @details This header defines the complete communication protocol between clients and server,
 *          including message types, request/response codes, data structures, and cryptographic
 *          constants. The protocol supports secure messaging with RSA and AES encryption.
 */

#pragma once
#include <cstdint>

/**
 * @brief Type definitions for protocol elements
 * @details These typedefs ensure consistent data types across the entire communication system
 */
using messageID_t = uint32_t;   ///< Unique identifier for messages in the system
using csize_t = uint32_t;       ///< Size type for content, payload and messages (32-bit unsigned)
using code_t = uint16_t;        ///< Response/request code identifiers
using version_t = uint8_t;      ///< Protocol version information
using messageType_t = uint8_t;  ///< Type of message being transmitted

/**
 * @brief Default initialization value for protocol structures
 * @details Used to initialize numeric fields in protocol structures
 */
constexpr int DEFAULT_VALUE = 0;

/**
 * @brief Protocol constants defining cryptographic and data sizes
 * @details These constants ensure consistent data handling across the system
 */
constexpr version_t PROTOCOL_VERSION = 2;           ///< Current protocol version
constexpr size_t REQUEST_TYPES_COUNT = 5;          ///< Total number of request types
constexpr size_t RESPONSE_TYPES_COUNT = 6;         ///< Total number of response types
constexpr size_t CLIENT_ID_LENGTH = 16;            ///< UUID length in bytes
constexpr size_t SYMMETRIC_KEY_LENGTH = 16;        ///< AES key length in bytes
constexpr size_t PUBLIC_KEY_LENGTH = 160;          ///< RSA public key length in bytes
constexpr size_t CLIENT_NAME_MAX_LENGTH = 255;     ///< Maximum username length

/**
 * @brief Message type enumeration for different communication modes
 * @details Defines the four main message types used in client-to-client communication
 */
enum MessageTypeEnum : messageType_t
{
	MSG_SYMMETRIC_KEY_REQUEST = 1,   ///< Request for symmetric key exchange (empty content)
	MSG_SYMMETRIC_KEY_SEND = 2,		 ///< Symmetric key encrypted with destination client's public key
	MSG_TEXT = 3,					 ///< Text message encrypted with symmetric key
	MSG_FILE = 4					 ///< File content encrypted with symmetric key
};

/**
 * @brief Request codes for client-server communication
 * @details Defines all client-initiated requests to the server
 */
enum RequestCodeEnum : code_t
{
	REQUEST_REGISTRATION = 600,   ///< Client registration request (UUID ignored)
	REQUEST_CLIENTS_LIST = 601,   ///< Request for list of registered clients (empty payload)
	REQUEST_PUBLIC_KEY = 602,     ///< Request for specific client's public key
	REQUEST_SEND_MSG = 603,       ///< Request to send message to another client
	REQUEST_PENDING_MSG = 604     ///< Request for pending messages (empty payload)
};

/**
 * @brief Response codes for server-client communication
 * @details Defines all server responses to client requests
 */
enum ResponseCodeEnum : code_t
{
	RESPONSE_REGISTRATION = 2100, ///< Registration response with client ID
	RESPONSE_USERS = 2101,        ///< Response with list of registered users
	RESPONSE_PUBLIC_KEY = 2102,   ///< Response with requested public key
	RESPONSE_MSG_SENT = 2103,     ///< Confirmation of message sent
	RESPONSE_PENDING_MSG = 2104,  ///< Response with pending messages
	RESPONSE_ERROR = 9000         ///< Error response (empty payload)
};

#pragma pack(push, 1) // Begin 1-byte alignment for network transmission

/**
 * @brief Client identifier structure using UUID
 * @details Represents a unique 16-byte identifier for each client in the system
 */
struct ClientIdStruct
{
	uint8_t uuid[CLIENT_ID_LENGTH]; ///< 16-byte UUID for client identification
	
	/**
	 * @brief Default constructor initializes UUID to zero
	 */
	ClientIdStruct() : uuid{ DEFAULT_VALUE } {}

	/**
	 * @brief Equality comparison operator
	 * @param[in] other Client ID to compare with
	 * @return true if UUIDs are identical, false otherwise
	 */
	bool operator==(const ClientIdStruct& other) const {
		for (size_t i = 0; i < CLIENT_ID_LENGTH; ++i)
			if (uuid[i] != other.uuid[i])
				return false;
		return true;
	}

	/**
	 * @brief Inequality comparison operator
	 * @param[in] other Client ID to compare with
	 * @return true if UUIDs are different, false otherwise
	 */
	bool operator!=(const ClientIdStruct& other) const {
		return !(*this == other);
	}
};

/**
 * @brief Client name structure for display purposes
 * @details Stores null-terminated username with maximum length constraint
 */
struct ClientNameStruct
{
	uint8_t name[CLIENT_NAME_MAX_LENGTH]; ///< Null-terminated username string
	
	/**
	 * @brief Default constructor initializes name to empty string
	 */
	ClientNameStruct() : name{ '\0' } {}
};

/**
 * @brief Public key structure for RSA encryption
 * @details Stores 160-byte RSA public key for secure communication
 */
struct PublicKeyStruct
{
	uint8_t publicKey[PUBLIC_KEY_LENGTH]; ///< RSA public key data
	
	/**
	 * @brief Default constructor initializes key to zero
	 */
	PublicKeyStruct() : publicKey{ DEFAULT_VALUE } {}
};

/**
 * @brief Symmetric key structure for AES encryption
 * @details Stores 16-byte AES key for session encryption
 */
struct SymmetricKeyStruct
{
	uint8_t symmetricKey[SYMMETRIC_KEY_LENGTH]; ///< AES symmetric key data
	
	/**
	 * @brief Default constructor initializes key to zero
	 */
	SymmetricKeyStruct() : symmetricKey{ DEFAULT_VALUE } {}
};

/**
 * @brief Request header structure for all client requests
 * @details Contains metadata for all outgoing requests including client ID, version, and payload size
 */
struct RequestHeaderStruct
{
	ClientIdStruct       clientId;     ///< Source client identifier
	const version_t version;           ///< Protocol version (constant)
	const code_t    code;              ///< Request type code (constant)
	csize_t         payloadSize;       ///< Size of request payload in bytes
	
	/**
	 * @brief Constructor for requests without client ID
	 * @param[in] reqCode Request type code
	 */
	RequestHeaderStruct(const code_t reqCode) : version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
	
	/**
	 * @brief Constructor for requests with client ID
	 * @param[in] id Source client identifier
	 * @param[in] reqCode Request type code
	 */
	RequestHeaderStruct(const ClientIdStruct& id, const code_t reqCode) : clientId(id), version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
};

/**
 * @brief Response header structure for all server responses
 * @details Contains metadata for all incoming responses including version, code, and payload size
 */
struct ResponseHeaderStruct
{
	version_t version;     ///< Protocol version
	code_t    code;        ///< Response type code
	csize_t   payloadSize; ///< Size of response payload in bytes
	
	/**
	 * @brief Default constructor initializes all fields to zero
	 */
	ResponseHeaderStruct() : version(DEFAULT_VALUE), code(DEFAULT_VALUE), payloadSize(DEFAULT_VALUE) {}
};

/**
 * @brief Registration request structure
 * @details Used when a new client registers with the server
 */
struct RequestRegistrationStruct
{
	RequestHeaderStruct header; ///< Standard request header
	struct
	{
		ClientNameStruct clientName;     ///< Client's display name
		PublicKeyStruct  clientPublicKey; ///< Client's RSA public key
	}payload; ///< Registration payload data
	
	/**
	 * @brief Default constructor initializes header with registration code
	 */
	RequestRegistrationStruct() : header(REQUEST_REGISTRATION) {}
};

/**
 * @brief Registration response structure
 * @details Server response containing the assigned client ID
 */
struct ResponseRegistrationStruct
{
	ResponseHeaderStruct header; ///< Standard response header
	ClientIdStruct       payload; ///< Assigned client identifier
};

/**
 * @brief Client list request structure
 * @details Used to request the list of all registered clients
 */
struct RequestClientsListStruct
{
	RequestHeaderStruct header; ///< Standard request header with client ID
	
	/**
	 * @brief Constructor initializes header with client ID and list request code
	 * @param[in] id Source client identifier
	 */
	RequestClientsListStruct(const ClientIdStruct& id) : header(id, REQUEST_CLIENTS_LIST) {}
};

/**
 * @brief Client list response structure
 * @details Server response containing the list of registered clients
 */
struct ResponseClientsListStruct
{
	ResponseHeaderStruct header; ///< Standard response header
	// Payload contains variable number of client entries
};

/**
 * @brief Public key request structure
 * @details Used to request a specific client's public key
 */
struct RequestPublicKeyStruct
{
	RequestHeaderStruct header; ///< Standard request header
	ClientIdStruct      payload; ///< Target client identifier
	
	/**
	 * @brief Constructor initializes header with client ID and public key request code
	 * @param[in] id Source client identifier
	 */
	RequestPublicKeyStruct(const ClientIdStruct& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

/**
 * @brief Public key response structure
 * @details Server response containing the requested client's public key
 */
struct ResponsePublicKeyStruct
{
	ResponseHeaderStruct header; ///< Standard response header
	struct
	{
		ClientIdStruct   clientId;      ///< Target client identifier
		PublicKeyStruct  clientPublicKey; ///< Client's RSA public key
	}payload; ///< Public key response payload
};

/**
 * @brief Message sending request structure
 * @details Used to send encrypted messages to other clients
 */
struct RequestSendMessageStruct
{
	RequestHeaderStruct header; ///< Standard request header
	struct PayloadHeaderStruct
	{
		ClientIdStruct           clientId;   ///< Destination client identifier
		const messageType_t messageType;     ///< Type of message being sent
		csize_t             contentSize;     ///< Size of encrypted content
		
		/**
		 * @brief Constructor initializes message type
		 * @param[in] type Message type (text, file, etc.)
		 */
		PayloadHeaderStruct(const messageType_t type) : messageType(type), contentSize(DEFAULT_VALUE) {}
	}payloadHeader; ///< Message payload header
	
	/**
	 * @brief Constructor initializes header and payload header
	 * @param[in] id Source client identifier
	 * @param[in] type Message type to send
	 */
	RequestSendMessageStruct(const ClientIdStruct& id, const messageType_t type) : header(id, REQUEST_SEND_MSG), payloadHeader(type) {}
};

/**
 * @brief Message sent confirmation response structure
 * @details Server confirmation that a message was successfully sent
 */
struct ResponseMessageSentStruct
{
	ResponseHeaderStruct header; ///< Standard response header
	struct PayloadStruct
	{
		ClientIdStruct   clientId;  ///< Destination client identifier
		messageID_t messageId;      ///< Unique message identifier
		
		/**
		 * @brief Default constructor initializes message ID to zero
		 */
		PayloadStruct() : messageId(DEFAULT_VALUE) {}
	}payload; ///< Message confirmation payload
};

/**
 * @brief Pending messages request structure
 * @details Used to retrieve messages waiting for the client
 */
struct RequestMessagesStruct
{
	RequestHeaderStruct header; ///< Standard request header
	
	/**
	 * @brief Constructor initializes header with client ID and pending messages request code
	 * @param[in] id Source client identifier
	 */
	RequestMessagesStruct(const ClientIdStruct& id) : header(id, REQUEST_PENDING_MSG) {}
};

/**
 * @brief Pending messages response structure
 * @details Server response containing all pending messages for the client
 */
struct ResponsePendingMessagesStruct
{
	ResponseHeaderStruct header; ///< Standard response header
	// Payload contains variable number of pending message structures
};

/**
 * @brief Pending message structure for individual messages
 * @details Represents a single pending message in the response
 */
struct PendingMessageStruct
{
	ClientIdStruct  clientId;     ///< Source client identifier
	messageID_t		messageId;     ///< Unique message identifier
	messageType_t	messageType;   ///< Type of message (text, file, etc.)
	csize_t			messageSize;   ///< Size of encrypted message content
	
	/**
	 * @brief Default constructor initializes fields to zero
	 */
	PendingMessageStruct() : messageId(DEFAULT_VALUE), messageType(DEFAULT_VALUE), messageSize(DEFAULT_VALUE) {}
};

#pragma pack(pop) // End 1-byte alignment
