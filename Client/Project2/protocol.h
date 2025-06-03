/**
 * @author Natanel Maor Fishman
 * @file   protocol.h
 * @brief  Establishes client-server communication standards as specified in requirements.
 * @note   All data structures use 1-byte alignment through pragma pack(push, 1) directive.
 */

#pragma once
#include <cstdint>

// Types for protocol elements
using messageID_t = uint32_t;   // Unique identifier for messages in the system
using csize_t = uint32_t;       // Size type for content, payload and messages (32-bit unsigned)
using code_t = uint16_t;        // Response/request code identifiers
using version_t = uint8_t;      // Protocol version information
using messageType_t = uint8_t;  // Type of message being transmitted

// Default initialization value
constexpr int DEFAULT_VALUE = 0;

// Protocol constants (in bytes)
constexpr version_t PROTOCOL_VERSION = 2;
constexpr size_t REQUEST_TYPES_COUNT = 5;
constexpr size_t RESPONSE_TYPES_COUNT = 6;
constexpr size_t CLIENT_ID_LENGTH = 16;
constexpr size_t SYMMETRIC_KEY_LENGTH = 16;
constexpr size_t PUBLIC_KEY_LENGTH = 160;
constexpr size_t CLIENT_NAME_MAX_LENGTH = 255;

// Message types (1-4)
enum MessageTypeEnum : messageType_t
{
	MSG_SYMMETRIC_KEY_REQUEST = 1,   // Empty content (contentSize = 0)
	MSG_SYMMETRIC_KEY_SEND = 2,		 // Symmetric key encrypted with destination client's public key
	MSG_TEXT = 3,					 // Message encrypted with symmetric key
	MSG_FILE = 4					 // File encrypted with symmetric key
};

// Request codes (600-604)
enum RequestCodeEnum : code_t
{
	REQUEST_REGISTRATION = 600,   // UUID ignored
	REQUEST_CLIENTS_LIST = 601,   // Empty payload
	REQUEST_PUBLIC_KEY = 602,
	REQUEST_SEND_MSG = 603,
	REQUEST_PENDING_MSG = 604     // Empty payload
};

// Response codes (2100-9000)
enum ResponseCodeEnum : code_t
{
	RESPONSE_REGISTRATION = 2100,
	RESPONSE_USERS = 2101,
	RESPONSE_PUBLIC_KEY = 2102,
	RESPONSE_MSG_SENT = 2103,
	RESPONSE_PENDING_MSG = 2104,
	RESPONSE_ERROR = 9000    // Empty payload
};

#pragma pack(push, 1) // Begin 1-byte alignment

// Client identifier structure
struct ClientIdStruct
{
	uint8_t uuid[CLIENT_ID_LENGTH];
	ClientIdStruct() : uuid{ DEFAULT_VALUE } {}

	bool operator==(const ClientIdStruct& other) const {
		for (size_t i = 0; i < CLIENT_ID_LENGTH; ++i)
			if (uuid[i] != other.uuid[i])
				return false;
		return true;
	}

	bool operator!=(const ClientIdStruct& other) const {
		return !(*this == other);
	}

};

// Client name structure
struct ClientNameStruct
{
	uint8_t name[CLIENT_NAME_MAX_LENGTH]; // Null-terminated
	ClientNameStruct() : name{ '\0' } {}
};

// Public key structure
struct PublicKeyStruct
{
	uint8_t publicKey[PUBLIC_KEY_LENGTH]; 
	PublicKeyStruct() : publicKey{ DEFAULT_VALUE } {}
};

// Symmetric key structure
struct SymmetricKeyStruct
{
	uint8_t symmetricKey[SYMMETRIC_KEY_LENGTH];
	SymmetricKeyStruct() : symmetricKey{ DEFAULT_VALUE } {}
};

// Request header structure
struct RequestHeaderStruct
{
	ClientIdStruct       clientId;
	const version_t version;
	const code_t    code;
	csize_t         payloadSize;
	RequestHeaderStruct(const code_t reqCode) : version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
	RequestHeaderStruct(const ClientIdStruct& id, const code_t reqCode) : clientId(id), version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
};

// Response header structure
struct ResponseHeaderStruct
{
	version_t version;
	code_t    code;
	csize_t   payloadSize;
	ResponseHeaderStruct() : version(DEFAULT_VALUE), code(DEFAULT_VALUE), payloadSize(DEFAULT_VALUE) {}
};


struct RequestRegistrationStruct
{
	RequestHeaderStruct header;
	struct
	{
		ClientNameStruct clientName;
		PublicKeyStruct  clientPublicKey;
	}payload;
	RequestRegistrationStruct() : header(REQUEST_REGISTRATION) {}
};

// Response structure for registration
struct ResponseRegistrationStruct
{
	ResponseHeaderStruct header;
	ClientIdStruct       payload;
};

//
struct RequestClientsListStruct
{
	RequestHeaderStruct header;
	RequestClientsListStruct(const ClientIdStruct& id) : header(id, REQUEST_CLIENTS_LIST) {}
};

struct ResponseClientsListStruct
{
	ResponseHeaderStruct header;
};

// Request structure for public key
struct RequestPublicKeyStruct
{
	RequestHeaderStruct header;
	ClientIdStruct      payload;
	RequestPublicKeyStruct(const ClientIdStruct& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

// Response structure for public key
struct ResponsePublicKeyStruct
{
	ResponseHeaderStruct header;
	struct
	{
		ClientIdStruct   clientId;
		PublicKeyStruct  clientPublicKey;
	}payload;
};

// Request structure for sending message
struct RequestSendMessageStruct
{
	RequestHeaderStruct header;
	struct PayloadHeaderStruct
	{
		ClientIdStruct           clientId;   // destination client
		const messageType_t messageType;
		csize_t             contentSize;
		PayloadHeaderStruct(const messageType_t type) : messageType(type), contentSize(DEFAULT_VALUE) {}
	}payloadHeader;
	RequestSendMessageStruct(const ClientIdStruct& id, const messageType_t type) : header(id, REQUEST_SEND_MSG), payloadHeader(type) {}
};

// Response structure for message sent
struct ResponseMessageSentStruct
{
	ResponseHeaderStruct header;
	struct PayloadStruct
	{
		ClientIdStruct   clientId;
		messageID_t messageId;
		PayloadStruct() : messageId(DEFAULT_VALUE) {}
	}payload;
};

// Request structure for pending messages
struct RequestMessagesStruct
{
	RequestHeaderStruct header;
	RequestMessagesStruct(const ClientIdStruct& id) : header(id, REQUEST_PENDING_MSG) {}
};

// Response structure for pending messages
struct PendingMessageStruct
{
	ClientIdStruct  clientId;
	messageID_t		messageId;
	messageType_t	messageType;
	csize_t			messageSize;
	PendingMessageStruct() : messageId(DEFAULT_VALUE), messageType(DEFAULT_VALUE), messageSize(DEFAULT_VALUE) {}
};

#pragma pack(pop) // End 1-byte alignment
