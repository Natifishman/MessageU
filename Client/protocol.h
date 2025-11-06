/**
 * @file        protocol.h
 * @author      Natanel Maor Fishman
 * @brief       Establishes client-server communication standards and protocol structures.
 * @details     Defines all protocol constants, enums, and packed data structures for MessageU client-server communication.
 *              All data structures use 1-byte alignment for network compatibility.
 * @version     2.0
 * @date        2025
 * @note        All data structures use 1-byte alignment through pragma pack(push, 1) directive.
 */

#pragma once

// ================================
// Standard Library Includes
// ================================
#include <cstdint>

// ================================
// Type Aliases
// ================================

using messageID_t = uint32_t;   ///< Unique identifier for messages in the system
using csize_t = uint32_t;       ///< Size type for content, payload and messages (32-bit unsigned)
using code_t = uint16_t;        ///< Response/request code identifiers
using version_t = uint8_t;      ///< Protocol version information
using messageType_t = uint8_t;  ///< Type of message being transmitted

// ================================
// Protocol Constants
// ================================

constexpr int DEFAULT_VALUE = 0;                ///< Default initialization value
constexpr version_t PROTOCOL_VERSION = 2;       ///< Protocol version
constexpr size_t REQUEST_TYPES_COUNT = 5;       ///< Number of request types
constexpr size_t RESPONSE_TYPES_COUNT = 6;      ///< Number of response types
constexpr size_t CLIENT_ID_LENGTH = 16;         ///< Length of client ID in bytes
constexpr size_t SYMMETRIC_KEY_LENGTH = 16;     ///< Length of symmetric key in bytes
constexpr size_t PUBLIC_KEY_LENGTH = 160;       ///< Length of public key in bytes
constexpr size_t CLIENT_NAME_MAX_LENGTH = 255;  ///< Maximum length of client name (null-terminated)

// ================================
// Enumerations
// ================================

/**
 * @enum MessageTypeEnum
 * @brief Message types for protocol communication
 * @details Enumerates all supported message types for client-server communication.
 */
enum MessageTypeEnum : messageType_t
{
	MSG_SYMMETRIC_KEY_REQUEST = 1,   ///< Empty content (contentSize = 0)
	MSG_SYMMETRIC_KEY_SEND = 2,      ///< Symmetric key encrypted with destination client's public key
	MSG_TEXT = 3,                    ///< Message encrypted with symmetric key
	MSG_FILE = 4                     ///< File encrypted with symmetric key
};

/**
 * @enum RequestCodeEnum
 * @brief Request codes for protocol communication
 * @details Enumerates all supported request codes for client-server communication.
 */
enum RequestCodeEnum : code_t
{
	REQUEST_REGISTRATION = 600,   ///< Registration request (UUID ignored)
	REQUEST_CLIENTS_LIST = 601,   ///< Request for list of clients (empty payload)
	REQUEST_PUBLIC_KEY = 602,     ///< Request for public key
	REQUEST_SEND_MSG = 603,       ///< Send message request
	REQUEST_PENDING_MSG = 604     ///< Request for pending messages (empty payload)
};

/**
 * @enum ResponseCodeEnum
 * @brief Response codes for protocol communication
 * @details Enumerates all supported response codes for client-server communication.
 */
enum ResponseCodeEnum : code_t
{
	RESPONSE_REGISTRATION = 2100, ///< Registration response
	RESPONSE_USERS = 2101,        ///< Users list response
	RESPONSE_PUBLIC_KEY = 2102,   ///< Public key response
	RESPONSE_MSG_SENT = 2103,     ///< Message sent response
	RESPONSE_PENDING_MSG = 2104,  ///< Pending messages response
	RESPONSE_ERROR = 9000         ///< Error response (empty payload)
};

// ================================
// Packed Data Structures
// ================================

#pragma pack(push, 1) // Begin 1-byte alignment

/**
 * @struct ClientIdStruct
 * @brief Unique client identifier structure
 * @details 16-byte UUID for client identification in the protocol.
 */
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

/**
 * @struct ClientNameStruct
 * @brief Client name structure (null-terminated)
 * @details Holds the client's display name, up to 255 bytes.
 */
struct ClientNameStruct
{
	uint8_t name[CLIENT_NAME_MAX_LENGTH]; ///< Null-terminated client name
	ClientNameStruct() : name{ '\0' } {}
};

/**
 * @struct PublicKeyStruct
 * @brief Public key structure
 * @details Holds the client's RSA public key (160 bytes).
 */
struct PublicKeyStruct
{
	uint8_t publicKey[PUBLIC_KEY_LENGTH];
	PublicKeyStruct() : publicKey{ DEFAULT_VALUE } {}
};

/**
 * @struct SymmetricKeyStruct
 * @brief Symmetric key structure
 * @details Holds the AES symmetric key (16 bytes).
 */
struct SymmetricKeyStruct
{
	uint8_t symmetricKey[SYMMETRIC_KEY_LENGTH];
	SymmetricKeyStruct() : symmetricKey{ DEFAULT_VALUE } {}
};

/**
 * @struct RequestHeaderStruct
 * @brief Request header for all client requests
 * @details Contains client ID, protocol version, request code, and payload size.
 */
struct RequestHeaderStruct
{
	ClientIdStruct       clientId;   ///< Client unique identifier
	const version_t      version;    ///< Protocol version
	const code_t         code;       ///< Request code
	csize_t              payloadSize;///< Size of payload in bytes
	RequestHeaderStruct(const code_t reqCode) : version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
	RequestHeaderStruct(const ClientIdStruct& id, const code_t reqCode) : clientId(id), version(PROTOCOL_VERSION), code(reqCode), payloadSize(DEFAULT_VALUE) {}
};

/**
 * @struct ResponseHeaderStruct
 * @brief Response header for all server responses
 * @details Contains protocol version, response code, and payload size.
 */
struct ResponseHeaderStruct
{
	version_t version;   ///< Protocol version
	code_t    code;      ///< Response code
	csize_t   payloadSize;///< Size of payload in bytes
	ResponseHeaderStruct() : version(DEFAULT_VALUE), code(DEFAULT_VALUE), payloadSize(DEFAULT_VALUE) {}
};

// ================================
// Request/Response Structures
// ================================

/**
 * @struct RequestRegistrationStruct
 * @brief Registration request structure
 * @details Used for client registration, includes client name and public key.
 */
struct RequestRegistrationStruct
{
	RequestHeaderStruct header; ///< Request header
	struct
	{
		ClientNameStruct clientName;      ///< Client name
		PublicKeyStruct  clientPublicKey; ///< Client public key
	}payload;
	RequestRegistrationStruct() : header(REQUEST_REGISTRATION) {}
};

/**
 * @struct ResponseRegistrationStruct
 * @brief Registration response structure
 * @details Contains the assigned client ID after successful registration.
 */
struct ResponseRegistrationStruct
{
	ResponseHeaderStruct header; ///< Response header
	ClientIdStruct       payload;///< Assigned client ID
};

/**
 * @struct RequestClientsListStruct
 * @brief Request for clients list structure
 * @details Used to request the list of registered clients.
 */
struct RequestClientsListStruct
{
	RequestHeaderStruct header; ///< Request header
	RequestClientsListStruct(const ClientIdStruct& id) : header(id, REQUEST_CLIENTS_LIST) {}
};

/**
 * @struct ResponseClientsListStruct
 * @brief Response for clients list structure
 * @details Used to respond with the list of registered clients.
 */
struct ResponseClientsListStruct
{
	ResponseHeaderStruct header; ///< Response header
};

/**
 * @struct RequestPublicKeyStruct
 * @brief Request for public key structure
 * @details Used to request the public key of a specific client.
 */
struct RequestPublicKeyStruct
{
	RequestHeaderStruct header; ///< Request header
	ClientIdStruct      payload;///< Target client ID
	RequestPublicKeyStruct(const ClientIdStruct& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

/**
 * @struct ResponsePublicKeyStruct
 * @brief Response for public key structure
 * @details Contains the public key of the requested client.
 */
struct ResponsePublicKeyStruct
{
	ResponseHeaderStruct header; ///< Response header
	struct
	{
		ClientIdStruct   clientId;      ///< Target client ID
		PublicKeyStruct  clientPublicKey;///< Public key
	}payload;
};

/**
 * @struct RequestSendMessageStruct
 * @brief Request to send a message structure
 * @details Used to send a message to another client.
 */
struct RequestSendMessageStruct
{
	RequestHeaderStruct header; ///< Request header
	struct PayloadHeaderStruct
	{
		ClientIdStruct           clientId;   ///< Destination client ID
		const messageType_t      messageType;///< Message type
		csize_t                  contentSize;///< Size of message content
		PayloadHeaderStruct(const messageType_t type) : messageType(type), contentSize(DEFAULT_VALUE) {}
	}payloadHeader;
	RequestSendMessageStruct(const ClientIdStruct& id, const messageType_t type) : header(id, REQUEST_SEND_MSG), payloadHeader(type) {}
};

/**
 * @struct ResponseMessageSentStruct
 * @brief Response for message sent structure
 * @details Contains the message ID and destination client ID.
 */
struct ResponseMessageSentStruct
{
	ResponseHeaderStruct header; ///< Response header
	struct PayloadStruct
	{
		ClientIdStruct   clientId; ///< Destination client ID
		messageID_t      messageId;///< Message ID
		PayloadStruct() : messageId(DEFAULT_VALUE) {}
	}payload;
};

/**
 * @struct RequestMessagesStruct
 * @brief Request for pending messages structure
 * @details Used to request all pending messages for a client.
 */
struct RequestMessagesStruct
{
	RequestHeaderStruct header; ///< Request header
	RequestMessagesStruct(const ClientIdStruct& id) : header(id, REQUEST_PENDING_MSG) {}
};

/**
 * @struct PendingMessageStruct
 * @brief Structure for a single pending message
 * @details Contains metadata for a pending message.
 */
struct PendingMessageStruct
{
	ClientIdStruct  clientId;    ///< Sender client ID
	messageID_t     messageId;   ///< Message ID
	messageType_t   messageType; ///< Message type
	csize_t         messageSize; ///< Size of message content
	PendingMessageStruct() : messageId(DEFAULT_VALUE), messageType(DEFAULT_VALUE), messageSize(DEFAULT_VALUE) {}
};

#pragma pack(pop) // End 1-byte alignment
