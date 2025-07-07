"""
MessageU - Protocol Definition
===========================
Author: Natanel Maor Fishman
File: protocol.py
===========================
Defines the communication protocol for the MessageU messaging system.
Establishes standardized message formats for client-server communication with
proper binary serialization and deserialization mechanisms.

Version: 2.0
"""

import struct
from enum import Enum

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


# Enumeration of request codes sent from client to server
class RequestCode(Enum):
    REGISTRATION = 600  # Registration request
    USERS_LIST = 601  # Request users list (no payload, payloadSize = 0)
    PUBLIC_KEY = 602  # Request public key for a specific user
    SEND_MESSAGE = 603  # Send a message to another user
    PENDING_MESSAGES = 604  # Request pending messages (no payload, payloadSize = 0)


# Enumeration of response codes sent from server to client
class ResponseCode(Enum):
    REGISTRATION_SUCCESS = 2100  # Registration completed successfully
    USERS_LIST = 2101  # List of registered users
    PUBLIC_KEY = 2102  # Public key for requested user
    MESSAGE_SENT = 2103  # Message sent successfully
    PENDING_MESSAGES = 2104  # List of pending messages
    ERROR = 9000  # Error occurred (no payload, payloadSize = 0)


class RequestHeader:
    """Base header for all client requests"""

    def __init__(self):
        self.clientID = b""  # Client's unique ID
        self.version = DEFAULT_VALUE  # Protocol version (1 byte)
        self.code = DEFAULT_VALUE  # Request code (2 bytes)
        self.payloadSize = DEFAULT_VALUE  # Size of payload in bytes (4 bytes)
        self.SIZE = CLIENT_ID_LENGTH + HEADER_SIZE

    def unpack(self, data):
        """
        Unpack binary data into request header fields using little endian format.
        data: Binary data containing the request header.
        Returns: True if unpacking was successful, False otherwise.
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


class ResponseHeader:
    """Base header for all server responses"""

    def __init__(self, code):
        self.version = SERVER_VERSION  # Protocol version (1 byte)
        self.code = code  # Response code (2 bytes)
        self.payloadSize = DEFAULT_VALUE  # Size of payload in bytes (4 bytes)
        self.SIZE = HEADER_SIZE

    def pack(self):
        """
        Pack response header fields into binary data using little endian format.
        Returns: Packed binary data
        """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""

    def unpack(self, data):
        """
        Unpack binary data into response header fields.
        Args: data: Binary data containing the response header
        Returns: True if unpacking was successful, False otherwise
        """
        try:
            self.version, self.code, self.payloadSize = struct.unpack(
                "<BHL", data[: self.SIZE]
            )
            return True
        except:
            return False


class RegistrationRequest:
    """Request structure for new client registration"""

    def __init__(self):
        self.header = RequestHeader()
        self.name = b""  # Client's username (null-terminated)
        self.publicKey = b""  # Client's public key

    def unpack(self, data):
        """
        Unpack binary data into registration request fields.
        Args - data: Binary data containing the registration request
        Returns: True if unpacking was successful, False otherwise
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

    def pack(self):
        """
        Pack registration request fields into binary data.
        Returns: Packed binary data
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
    """Response structure for successful client registration"""

    def __init__(self):
        self.header = ResponseHeader(ResponseCode.REGISTRATION_SUCCESS.value)
        self.clientID = b""  # Assigned client ID

    def pack(self):
        """
        Pack registration response fields into binary data.
        Returns: Packed binary data
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            return data
        except:
            return b""

    def unpack(self, data):
        """
        Unpack binary data into registration response fields.
        Args - data: Binary data containing the registration response
        Returns: True if unpacking was successful, False otherwise
        """
        try:
            if not self.header.unpack(data[: self.header.SIZE]):
                return False

            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s",
                data[self.header.SIZE : self.header.SIZE + CLIENT_ID_LENGTH],
            )[0]
            return True
        except:
            return False


class PublicKeyRequest:
    """Request structure for retrieving a client's public key"""

    def __init__(self):
        self.header = RequestHeader()
        self.clientID = b""  # Target client ID

    def unpack(self, data):
        """
        Unpack binary data into public key request fields.
        Args - data: Binary data containing the public key request
        Returns: True if unpacking was successful, False otherwise
        """
        if not self.header.unpack(data):
            return False

        try:
            # Extract client ID
            client_start = self.header.SIZE
            client_end = client_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[client_start:client_end]
            )[0]
            return True
        except:
            self.clientID = b""
            return False

    def pack(self):
        """
        Pack public key request fields into binary data.
        Returns: Packed binary data
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
    """Response structure for public key retrieval"""

    def __init__(self):
        self.header = ResponseHeader(ResponseCode.PUBLIC_KEY.value)
        self.clientID = b""  # Client ID
        self.publicKey = b""  # Client's public key

    def pack(self):
        """
        Pack public key response fields into binary data.
        Returns: Packed binary data
        """
        try:
            # Set payload size
            self.header.payloadSize = CLIENT_ID_LENGTH + PUBLIC_KEY_LENGTH

            # Pack header, client ID, and public key
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            data += struct.pack(f"<{PUBLIC_KEY_LENGTH}s", self.publicKey)
            return data
        except:
            return b""

    def unpack(self, data):
        """
        Unpack binary data into public key response fields.
        Args: data: Binary data containing the public key response
        Returns: True if unpacking was successful, False otherwise
        """
        try:
            if not self.header.unpack(data[: self.header.SIZE]):
                return False

            # Extract client ID
            offset = self.header.SIZE
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[offset : offset + CLIENT_ID_LENGTH]
            )[0]

            # Extract public key
            offset += CLIENT_ID_LENGTH
            self.publicKey = struct.unpack(
                f"<{PUBLIC_KEY_LENGTH}s", data[offset : offset + PUBLIC_KEY_LENGTH]
            )[0]
            return True
        except:
            return False


class MessageSendRequest:
    """Request structure for sending a message to another client"""

    def __init__(self):
        self.header = RequestHeader()
        self.clientID = b""  # Recipient's client ID
        self.messageType = DEFAULT_VALUE  # Message type (1 byte)
        self.contentSize = DEFAULT_VALUE  # Content size (4 bytes)
        self.content = b""  # Message content

    def unpack(self, conn, data):
        """
        Unpack binary data into message send request fields.
        For large messages, reads additional data from connection.
        Args -  conn: Socket connection to read additional data from
                data: Initial binary data chunk
        Returns: True if unpacking was successful, False otherwise
        """
        packet_size = len(data)

        if not self.header.unpack(data):
            return False

        try:
            # Extract recipient client ID
            client_start = self.header.SIZE
            client_end = client_start + CLIENT_ID_LENGTH
            self.clientID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[client_start:client_end]
            )[0]

            # Extract message type and content size
            offset = client_end
            self.messageType, self.contentSize = struct.unpack(
                "<BL", data[offset : offset + 5]
            )

            # Extract initial content chunk
            offset = self.header.SIZE + CLIENT_ID_LENGTH + 5
            bytes_read = packet_size - offset

            # Truncate to actual content size if needed
            if bytes_read > self.contentSize:
                bytes_read = self.contentSize

            if bytes_read > 0:
                self.content = struct.unpack(
                    f"<{bytes_read}s", data[offset : offset + bytes_read]
                )[0]
            else:
                bytes_read = 0
                self.content = b""

            # Read additional chunks for large messages
            while bytes_read < self.contentSize:
                chunk = conn.recv(packet_size)  # reuse same buffer size
                chunk_size = len(chunk)

                if not chunk:  # Connection closed
                    return False

                # Calculate remaining bytes to read
                remaining = self.contentSize - bytes_read
                if remaining < chunk_size:
                    chunk_size = remaining

                # Append chunk to content
                self.content += struct.unpack(f"<{chunk_size}s", chunk[:chunk_size])[0]
                bytes_read += chunk_size

            return True
        except:
            self.clientID = b""
            self.messageType = DEFAULT_VALUE
            self.contentSize = DEFAULT_VALUE
            self.content = b""
            return False

    def pack(self):
        """
        Pack message send request fields into binary data.
        Returns: Packed binary data
        """
        try:
            # Update content size
            self.contentSize = len(self.content)

            # Set header fields
            self.header.code = RequestCode.SEND_MESSAGE.value
            self.header.payloadSize = CLIENT_ID_LENGTH + 5 + self.contentSize

            # Pack header, recipient ID, message type, and content size
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}s", self.clientID)
            data += struct.pack("<BL", self.messageType, self.contentSize)

            # Pack content
            if self.contentSize > 0:
                data += struct.pack(f"<{self.contentSize}s", self.content)

            return data
        except:
            return b""


class MessageSentResponse:
    """Response structure for message sending confirmation"""

    def __init__(self):
        self.header = ResponseHeader(ResponseCode.MESSAGE_SENT.value)
        self.clientID = b""  # Recipient's client ID
        self.messageID = 0  # Assigned message ID

    def pack(self):
        """
        Pack message sent response fields into binary data.
        Returns: Packed binary data
        """
        try:
            # Set payload size
            self.header.payloadSize = CLIENT_ID_LENGTH + MSG_ID_SIZE

            # Pack header, client ID, and message ID
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_LENGTH}sL", self.clientID, self.messageID)
            return data
        except:
            return b""

    def unpack(self, data):
        """
        Unpack binary data into message sent response fields.
        Args - data: Binary data containing the message sent response
        Returns: True if unpacking was successful, False otherwise
        """
        try:
            if not self.header.unpack(data[: self.header.SIZE]):
                return False

            # Extract client ID and message ID
            offset = self.header.SIZE
            self.clientID, self.messageID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}sL",
                data[offset : offset + CLIENT_ID_LENGTH + MSG_ID_SIZE],
            )
            return True
        except:
            return False


class PendingMessage:
    """Structure for pending messages retrieved from server"""

    def __init__(self):
        self.MessageEngineID = b""  # Sender's client ID
        self.messageID = 0  # Message ID
        self.messageType = 0  # Message type
        self.messageSize = 0  # Message size
        self.content = b""  # Message content

    def pack(self):
        """
        Pack pending message fields into binary data.
        Returns: Packed binary data
        """
        try:
            # Pack sender ID, message ID, type, and size
            data = struct.pack(f"<{CLIENT_ID_LENGTH}s", self.MessageEngineID)
            data += struct.pack(
                "<LBL", self.messageID, self.messageType, self.messageSize
            )

            # Pack content
            if self.messageSize > 0:
                data += struct.pack(f"<{self.messageSize}s", self.content)

            return data
        except:
            return b""

    def unpack(self, data, offset=0):
        """
        Unpack binary data into pending message fields.
        Args -  data: Binary data containing the pending message
                offset: Starting offset in the data
        Returns: True if unpacking was successful, False otherwise and bytes read
        """
        try:
            # Extract sender ID
            start = offset
            end = start + CLIENT_ID_LENGTH
            self.MessageEngineID = struct.unpack(
                f"<{CLIENT_ID_LENGTH}s", data[start:end]
            )[0]

            # Extract message ID, type, and size
            start = end
            end = start + 9  # 4 (msgID) + 1 (type) + 4 (size)
            self.messageID, self.messageType, self.messageSize = struct.unpack(
                "<LBL", data[start:end]
            )

            # Extract content
            if self.messageSize > 0:
                start = end
                end = start + self.messageSize
                self.content = struct.unpack(f"<{self.messageSize}s", data[start:end])[
                    0
                ]
            else:
                self.content = b""

            # Return total bytes read
            return True, end - offset
        except:
            return False, 0


# Utility functions for message and client ID handling


def client_id_to_string(client_id):
    """
    Convert binary client ID to hexadecimal string representation.
    Args: client_id: Binary client ID
    Returns: Hexadecimal string representation
    """
    if not client_id:
        return ""
    if isinstance(client_id, bytes):
        return client_id.hex()
    return str(client_id)


def extract_pending_messages(data, count=None):
    """
    Extract multiple pending messages from a payload.
    Args -  data: Binary data containing pending messages
            count: Optional maximum number of messages to extract
    Returns: List of PendingMessage objects
    """
    messages = []
    offset = 0
    data_len = len(data)

    while offset < data_len:
        message = PendingMessage()
        success, bytes_read = message.unpack(data, offset)

        if not success:
            break

        messages.append(message)
        offset += bytes_read

        if count is not None and len(messages) >= count:
            break

    return messages


def validate_client_id(client_id):
    """
    Validate a client ID according to protocol requirements.
    Args: client_id: Client ID to validate (bytes or hex string)
    Returns: True if valid, False otherwise
    """
    if isinstance(client_id, str):
        # Convert hex string to bytes
        try:
            client_id = bytes.fromhex(client_id)
        except ValueError:
            return False

    # Check if it's bytes of the correct length
    return isinstance(client_id, bytes) and len(client_id) == CLIENT_ID_LENGTH


def validate_message_type(message_type):
    """
    Validate message type according to protocol requirements.
    Args: message_type: Message type value to validate
    Returns: True if valid, False otherwise
    """
    try:
        message_type = int(message_type)
        return 0 <= message_type <= MSG_TYPE_MAX
    except (ValueError, TypeError):
        return False


def create_error_response():
    """
    Create a generic error response with no payload.
    Returns: Packed error response
    """
    header = ResponseHeader(ResponseCode.ERROR.value)
    header.payloadSize = 0
    return header.pack()


def debug_request_header(header):
    """
    Generate debug information for a request header.
    Args - header: RequestHeader object
    Returns: String with formatted header information
    """
    if not isinstance(header, RequestHeader):
        return "Invalid header object"

    client_id = client_id_to_string(header.clientID)

    # Map code to readable enum value if possible
    code_name = "UNKNOWN"
    for code in RequestCode:
        if code.value == header.code:
            code_name = code.name

    return (
        f"RequestHeader [ClientID: {client_id}, Version: {header.version}, "
        f"Code: {header.code} ({code_name}), PayloadSize: {header.payloadSize}]"
    )


def debug_response_header(header):
    """
    Generate debug information for a response header.
    Args: header: ResponseHeader object

    Returns: String with formatted header information
    """
    if not isinstance(header, ResponseHeader):
        return "Invalid header object"

    # Map code to readable enum value if possible
    code_name = "UNKNOWN"
    for code in ResponseCode:
        if code.value == header.code:
            code_name = code.name

    return (
        f"ResponseHeader [Version: {header.version}, "
        f"Code: {header.code} ({code_name}), PayloadSize: {header.payloadSize}]"
    )