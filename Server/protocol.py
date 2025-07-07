"""
MessageU - Protocol Definition
==============================

Author: Natanel Maor Fishman
Version: 2.0
Date: 2025

Defines the communication protocol for the MessageU messaging system.
Establishes standardized message formats for client-server communication with
proper binary serialization and deserialization mechanisms.

This module provides the complete protocol specification including:
- Request and response message structures
- Binary serialization/deserialization
- Data validation and error handling
- Protocol constants and enumerations
"""

# ================================
# Standard Library Imports
# ================================

import struct
from enum import Enum
from typing import Optional

# ================================
# Protocol Constants
# ================================

# Protocol version and structure constants
SERVER_VERSION = 2  # Version 2 supports SQL Database
MSG_ID_SIZE = 4  # Size of message ID in bytes
HEADER_SIZE = 7  # Header size without clientID
CLIENT_ID_LENGTH = 16  # Size of client ID in bytes
PUBLIC_KEY_LENGTH = 160  # Size of public key in bytes
NAME_SIZE = 255  # Maximum size for names

# Protocol limits
MSG_TYPE_MAX = 0xFF  # Maximum message type value
MSG_ID_MAX = 0xFFFFFFFF  # Maximum message ID value

# Default initialization value
DEFAULT_VALUE = 0

# ================================
# Protocol Enumerations
# ================================


class RequestCode(Enum):
    """
    Enumeration of request codes sent from client to server.
    
    Defines all valid request types that clients can send to the server
    for various operations including registration, messaging, and data retrieval.
    """
    REGISTRATION = 600  # Registration request
    USERS_LIST = 601  # Request users list (no payload, payloadSize = 0)
    PUBLIC_KEY = 602  # Request public key for a specific user
    SEND_MESSAGE = 603  # Send a message to another user
    PENDING_MESSAGES = 604  # Request pending messages (no payload, payloadSize = 0)


class ResponseCode(Enum):
    """
    Enumeration of response codes sent from server to client.
    
    Defines all valid response types that the server can send to clients
    indicating success, failure, or data delivery status.
    """
    REGISTRATION_SUCCESS = 2100  # Registration completed successfully
    USERS_LIST = 2101  # List of registered users
    PUBLIC_KEY = 2102  # Public key for requested user
    MESSAGE_SENT = 2103  # Message sent successfully
    PENDING_MESSAGES = 2104  # List of pending messages
    ERROR = 9000  # Error occurred (no payload, payloadSize = 0)

# ================================
# Base Protocol Classes
# ================================


class RequestHeader:
    """
    Base header for all client requests.
    
    Contains common header fields that are present in all client requests
    including client identification, protocol version, and request metadata.
    
    Attributes:
        clientID: Client's unique identifier (16 bytes)
        version: Protocol version (1 byte)
        code: Request code (2 bytes)
        payloadSize: Size of payload in bytes (4 bytes)
        SIZE: Total header size including client ID
    """

    def __init__(self):
        """Initialize request header with default values."""
        self.clientID = b""  # Client's unique ID
        self.version = DEFAULT_VALUE  # Protocol version (1 byte)
        self.code = DEFAULT_VALUE  # Request code (2 bytes)
        self.payloadSize = DEFAULT_VALUE  # Size of payload in bytes (4 bytes)
        self.SIZE = CLIENT_ID_LENGTH + HEADER_SIZE

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into request header fields using little endian format.
        
        Args:
            data: Binary data containing the request header
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts client ID from first 16 bytes and header fields from
            the next 7 bytes using struct unpacking with little endian format.
        """
        try:
            # Extract client ID (first 16 bytes)
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[:CLIENT_ID_LENGTH]
            )[0]

            # Extract header fields from the next 7 bytes
            header_data = data[CLIENT_ID_LENGTH : CLIENT_ID_LENGTH + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack(
                "<BHL", header_data
            )
            return True
        except:
            self.__init__()  # reset values on failure
            return False

    def pack(self) -> bytes:
        """
        Pack request header fields into binary data.
        
        Returns:
            Packed binary data containing header information
            
        Details:
            Serializes header fields into binary format using little endian
            encoding for network transmission.
        """
        try:
            # Pack client ID
            data = struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            
            # Pack header fields
            data += struct.pack("<BHL", self.version, self.code, self.payloadSize)
            return data
        except:
            return b""


class ResponseHeader:
    """
    Base header for all server responses.
    
    Contains common header fields that are present in all server responses
    including protocol version, response code, and payload size information.
    
    Attributes:
        version: Protocol version (1 byte)
        code: Response code (2 bytes)
        payloadSize: Size of payload in bytes (4 bytes)
        SIZE: Total header size
    """

    def __init__(self, code: int):
        """
        Initialize response header with specified response code.
        
        Args:
            code: Response code to use for this response
        """
        self.version = SERVER_VERSION  # Protocol version (1 byte)
        self.code = code  # Response code (2 bytes)
        self.payloadSize = DEFAULT_VALUE  # Size of payload in bytes (4 bytes)
        self.SIZE = HEADER_SIZE

    def pack(self) -> bytes:
        """
        Pack response header fields into binary data using little endian format.
        
        Returns:
            Packed binary data containing header information
            
        Details:
            Serializes header fields into binary format for network transmission.
        """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into response header fields.
        
        Args:
            data: Binary data containing the response header
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts header fields from binary data using struct unpacking.
        """
        try:
            self.version, self.code, self.payloadSize = struct.unpack(
                "<BHL", data[: self.SIZE]
            )
            return True
        except:
            return False

# ================================
# Registration Protocol Classes
# ================================


class RegistrationRequest:
    """
    Request structure for new client registration.
    
    Contains all necessary information for registering a new client
    including username and public key for secure communication.
    
    Attributes:
        header: Request header with registration code
        name: Client's username (null-terminated)
        publicKey: Client's public key
    """

    def __init__(self):
        """Initialize registration request with empty fields."""
        self.header = RequestHeader()
        self.name = b""  # Client's username (null-terminated)
        self.publicKey = b""  # Client's public key

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into registration request fields.
        
        Args:
            data: Binary data containing the registration request
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts username and public key from binary data after parsing header.
            Handles null-terminated username strings properly.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract and process name (with null termination)
            name_data = data[self.header.SIZE : self.header.SIZE + NAME_SIZE]
            self.name = str(
                struct.unpack(f"<{NAME_SIZE}s", name_data)[0]
                .partition(b"\0")[0]  # Split at first null byte
                .decode("utf-8")
            )

            # Extract public key
            key_start = self.header.SIZE + NAME_SIZE
            key_end = key_start + PUBLIC_KEY_LENGTH
            self.publicKey = struct.unpack(
                f"<{PUBLIC_KEY_LENGTH}s", data[key_start:key_end]
            )[0]
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False

    def pack(self) -> bytes:
        """
        Pack registration request fields into binary data.
        
        Returns:
            Packed binary data containing registration information
            
        Details:
            Serializes username and public key into binary format with
            proper padding and null termination for username.
        """
        try:
            # Set header fields
            self.header.code = RequestCode.REGISTRATION.value
            self.header.payloadSize = NAME_SIZE + PUBLIC_KEY_LENGTH

            # Pack header
            data = self.header.pack()

            # Convert name to bytes if needed and pad with zeros
            if isinstance(self.name, str):
                name_bytes = self.name.encode("utf-8")
            else:
                name_bytes = self.name

            padded_name = name_bytes + b"\0" * (NAME_SIZE - len(name_bytes))
            data += struct.pack(f"<{NAME_SIZE}s", padded_name[:NAME_SIZE])

            # Pack public key
            data += struct.pack(f"<{PUBLIC_KEY_LENGTH}s", self.publicKey)
            return data
        except:
            return b""


class RegistrationResponse:
    """
    Response structure for successful client registration.
    
    Contains the assigned client ID that is returned to the client
    upon successful registration for future authentication.
    
    Attributes:
        header: Response header with success code
        clientID: Assigned client ID for the new client
    """

    def __init__(self):
        """Initialize registration response with success code."""
        self.header = ResponseHeader(ResponseCode.REGISTRATION_SUCCESS.value)
        self.clientID = b""  # Assigned client ID

    def pack(self) -> bytes:
        """
        Pack registration response fields into binary data.
        
        Returns:
            Packed binary data containing client ID
            
        Details:
            Serializes client ID into binary format for transmission to client.
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            return data
        except:
            return b""

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into registration response fields.
        
        Args:
            data: Binary data containing the registration response
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts client ID from binary response data.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract client ID
            id_start = self.header.SIZE
            id_end = id_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[id_start:id_end]
            )[0]
            return True
        except:
            self.clientID = b""
            return False

# ================================
# Public Key Protocol Classes
# ================================


class PublicKeyRequest:
    """
    Request structure for public key retrieval.
    
    Contains the target client ID for which the public key is requested.
    
    Attributes:
        header: Request header with public key request code
        clientID: Target client ID for key retrieval
    """

    def __init__(self):
        """Initialize public key request with empty fields."""
        self.header = RequestHeader()
        self.clientID = b""  # Target client ID

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into public key request fields.
        
        Args:
            data: Binary data containing the public key request
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts target client ID from binary request data.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract target client ID
            id_start = self.header.SIZE
            id_end = id_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[id_start:id_end]
            )[0]
            return True
        except:
            self.clientID = b""
            return False

    def pack(self) -> bytes:
        """
        Pack public key request fields into binary data.
        
        Returns:
            Packed binary data containing target client ID
            
        Details:
            Serializes target client ID into binary format for transmission.
        """
        try:
            # Set header fields
            self.header.code = RequestCode.PUBLIC_KEY.value
            self.header.payloadSize = CLIENT_ID_LENGTH

            # Pack header and client ID
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            return data
        except:
            return b""


class PublicKeyResponse:
    """
    Response structure for public key delivery.
    
    Contains the requested client's public key for secure communication setup.
    
    Attributes:
        header: Response header with public key response code
        clientID: Client ID for which the key belongs
        publicKey: Client's public key
    """

    def __init__(self):
        """Initialize public key response with empty fields."""
        self.header = ResponseHeader(ResponseCode.PUBLIC_KEY.value)
        self.clientID = b""  # Client ID
        self.publicKey = b""  # Public key

    def pack(self) -> bytes:
        """
        Pack public key response fields into binary data.
        
        Returns:
            Packed binary data containing client ID and public key
            
        Details:
            Serializes client ID and public key into binary format.
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            data += struct.pack(f"<{PUBLIC_KEY_LENGTH}s", self.publicKey)
            return data
        except:
            return b""

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into public key response fields.
        
        Args:
            data: Binary data containing the public key response
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts client ID and public key from binary response data.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract client ID
            id_start = self.header.SIZE
            id_end = id_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[id_start:id_end]
            )[0]

            # Extract public key
            key_start = id_end
            key_end = key_start + PUBLIC_KEY_LENGTH
            self.publicKey = struct.unpack(
                f"<{PUBLIC_KEY_LENGTH}s", data[key_start:key_end]
            )[0]
            return True
        except:
            self.clientID = b""
            self.publicKey = b""
            return False

# ================================
# Message Protocol Classes
# ================================


class MessageSendRequest:
    """
    Request structure for sending messages.
    
    Contains all necessary information for sending a message including
    recipient, message type, and encrypted content.
    
    Attributes:
        header: Request header with send message code
        clientID: Recipient's client ID
        messageType: Type of message being sent
        content: Encrypted message content
    """

    def __init__(self):
        """Initialize message send request with empty fields."""
        self.header = RequestHeader()
        self.clientID = b""  # Recipient's client ID
        self.messageType = DEFAULT_VALUE  # Message type
        self.content = b""  # Message content

    def unpack(self, conn, data: bytes) -> bool:
        """
        Unpack binary data into message send request fields.
        
        Args:
            conn: Connection object for reading additional data
            data: Binary data containing the message send request
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts recipient ID and message type from header, then reads
            variable-length content from the connection.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract recipient client ID
            id_start = self.header.SIZE
            id_end = id_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[id_start:id_end]
            )[0]

            # Extract message type
            type_start = id_end
            type_end = type_start + 1
            self.messageType = struct.unpack("<B", data[type_start:type_end])[0]

            # Read message content from connection
            if self.header.payloadSize > CLIENT_ID_LENGTH + 1:
                content_size = self.header.payloadSize - CLIENT_ID_LENGTH - 1
                self.content = conn.recv(content_size)
            else:
                self.content = b""

            return True
        except:
            self.clientID = b""
            self.messageType = DEFAULT_VALUE
            self.content = b""
            return False

    def pack(self) -> bytes:
        """
        Pack message send request fields into binary data.
        
        Returns:
            Packed binary data containing message information
            
        Details:
            Serializes recipient ID, message type, and content into binary format.
        """
        try:
            # Set header fields
            self.header.code = RequestCode.SEND_MESSAGE.value
            self.header.payloadSize = CLIENT_ID_LENGTH + 1 + len(self.content)

            # Pack header, recipient ID, and message type
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            data += struct.pack("<B", self.messageType)

            # Pack message content
            data += self.content
            return data
        except:
            return b""


class MessageSentResponse:
    """
    Response structure for message delivery confirmation.
    
    Contains confirmation that a message was successfully stored
    including the assigned message ID for tracking.
    
    Attributes:
        header: Response header with message sent code
        clientID: Recipient's client ID
        messageID: Assigned message ID
    """

    def __init__(self):
        """Initialize message sent response with success code."""
        self.header = ResponseHeader(ResponseCode.MESSAGE_SENT.value)
        self.clientID = b""  # Recipient's client ID
        self.messageID = DEFAULT_VALUE  # Assigned message ID

    def pack(self) -> bytes:
        """
        Pack message sent response fields into binary data.
        
        Returns:
            Packed binary data containing confirmation information
            
        Details:
            Serializes recipient ID and message ID into binary format.
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            data += struct.pack("<L", self.messageID)
            return data
        except:
            return b""

    def unpack(self, data: bytes) -> bool:
        """
        Unpack binary data into message sent response fields.
        
        Args:
            data: Binary data containing the message sent response
            
        Returns:
            True if unpacking was successful, False otherwise
            
        Details:
            Extracts recipient ID and message ID from binary response data.
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract recipient client ID
            id_start = self.header.SIZE
            id_end = id_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[id_start:id_end]
            )[0]

            # Extract message ID
            msg_id_start = id_end
            msg_id_end = msg_id_start + MSG_ID_SIZE
            self.messageID = struct.unpack("<L", data[msg_id_start:msg_id_end])[0]
            return True
        except:
            self.clientID = b""
            self.messageID = DEFAULT_VALUE
            return False


class PendingMessage:
    """
    Structure for pending message data.
    
    Contains all information about a pending message including
    sender, type, content, and metadata.
    
    Attributes:
        messageID: Unique message identifier
        MessageEngineID: Sender's client ID
        messageType: Type of message
        content: Encrypted message content
        messageSize: Size of message content
    """

    def __init__(self):
        """Initialize pending message with empty fields."""
        self.messageID = DEFAULT_VALUE  # Message ID
        self.MessageEngineID = b""  # Sender's client ID
        self.messageType = DEFAULT_VALUE  # Message type
        self.content = b""  # Message content
        self.messageSize = DEFAULT_VALUE  # Content size

    def pack(self) -> bytes:
        """
        Pack pending message fields into binary data.
        
        Returns:
            Packed binary data containing message information
            
        Details:
            Serializes all message fields into binary format for transmission.
        """
        try:
            data = struct.pack("<L", self.messageID)
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.MessageEngineID)
            data += struct.pack("<B", self.messageType)
            data += struct.pack("<L", self.messageSize)
            data += self.content
            return data
        except:
            return b""

    def unpack(self, data: bytes, offset: int = 0) -> int:
        """
        Unpack binary data into pending message fields.
        
        Args:
            data: Binary data containing the pending message
            offset: Starting offset in the data
            
        Returns:
            New offset after unpacking, or -1 on error
            
        Details:
            Extracts all message fields from binary data starting at the
            specified offset. Returns the new offset for processing multiple messages.
        """
        try:
            # Extract message ID
            msg_id_start = offset
            msg_id_end = msg_id_start + MSG_ID_SIZE
            self.messageID = struct.unpack("<L", data[msg_id_start:msg_id_end])[0]

            # Extract sender ID
            sender_start = msg_id_end
            sender_end = sender_start + CLIENT_ID_LENGTH
            self.MessageEngineID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[sender_start:sender_end]
            )[0]

            # Extract message type
            type_start = sender_end
            type_end = type_start + 1
            self.messageType = struct.unpack("<B", data[type_start:type_end])[0]

            # Extract message size
            size_start = type_end
            size_end = size_start + 4
            self.messageSize = struct.unpack("<L", data[size_start:size_end])[0]

            # Extract message content
            content_start = size_end
            content_end = content_start + self.messageSize
            self.content = data[content_start:content_end]

            return content_end
        except:
            return -1

# ================================
# Utility Functions
# ================================


def client_id_to_string(client_id: bytes) -> str:
    """
    Convert client ID bytes to hexadecimal string representation.
    
    Args:
        client_id: Client ID as bytes
        
    Returns:
        Hexadecimal string representation of client ID
        
    Details:
        Converts binary client ID to human-readable hex format
        for logging and debugging purposes.
    """
    try:
        return client_id.hex()
    except:
        return ""


def extract_pending_messages(data: bytes, count: Optional[int] = None) -> list:
    """
    Extract multiple pending messages from binary data.
    
    Args:
        data: Binary data containing multiple pending messages
        count: Number of messages to extract (None for all)
        
    Returns:
        List of PendingMessage objects
        
    Details:
        Parses binary data containing multiple pending messages
        and returns them as a list of PendingMessage objects.
    """
    messages = []
    offset = 0
    extracted_count = 0

    while offset < len(data) and (count is None or extracted_count < count):
        message = PendingMessage()
        new_offset = message.unpack(data, offset)
        
        if new_offset == -1:
            break
            
        messages.append(message)
        offset = new_offset
        extracted_count += 1

    return messages


def validate_client_id(client_id: bytes) -> bool:
    """
    Validate client ID format and length.
    
    Args:
        client_id: Client ID to validate
        
    Returns:
        True if client ID is valid, False otherwise
        
    Details:
        Checks that client ID has the correct length and format
        according to protocol specifications.
    """
    return (isinstance(client_id, bytes) and 
            len(client_id) == CLIENT_ID_LENGTH)


def validate_message_type(message_type: int) -> bool:
    """
    Validate message type value.
    
    Args:
        message_type: Message type to validate
        
    Returns:
        True if message type is valid, False otherwise
        
    Details:
        Checks that message type is within the valid range
        defined by protocol specifications.
    """
    return (isinstance(message_type, int) and 
            0 <= message_type <= MSG_TYPE_MAX)


def create_error_response() -> ResponseHeader:
    """
    Create a standardized error response header.
    
    Returns:
        ResponseHeader with error code
        
    Details:
        Creates a response header with the standard error code
        for indicating protocol or processing errors.
    """
    return ResponseHeader(ResponseCode.ERROR.value)


def debug_request_header(header: RequestHeader) -> str:
    """
    Create debug string representation of request header.
    
    Args:
        header: Request header to debug
        
    Returns:
        Debug string with header information
        
    Details:
        Creates a human-readable string containing all header
        fields for debugging and logging purposes.
    """
    return (f"RequestHeader: clientID={client_id_to_string(header.clientID)}, "
            f"version={header.version}, code={header.code}, "
            f"payloadSize={header.payloadSize}")


def debug_response_header(header: ResponseHeader) -> str:
    """
    Create debug string representation of response header.
    
    Args:
        header: Response header to debug
        
    Returns:
        Debug string with header information
        
    Details:
        Creates a human-readable string containing all header
        fields for debugging and logging purposes.
    """
    return (f"ResponseHeader: version={header.version}, code={header.code}, "
            f"payloadSize={header.payloadSize}")