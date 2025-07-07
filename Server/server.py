"""
Author: Natanel Maor Fishman

server.py: Core Server implementation for the MessageU secure messaging platform.
Manages socket connections, request processing, and client communication with
thread-safe mechanisms and comprehensive error handling.
version: 2.0
"""

import logging
import selectors
import uuid
import socket
import database
import protocol
from datetime import datetime
from typing import Dict, Callable, Optional, Tuple, Any


class Server:
    """
    MessageU server implementation handling client connections and message routing.
    Uses non-blocking sockets with selectors for efficient I/O multiplexing.
    """

    # Class constants
    DATABASE_PATH = "defensive.db"
    PACKET_SIZE = 1024  # Default packet size in bytes
    MAX_CONNECTIONS = 10  # Maximum number of queued connections
    NON_BLOCKING = False  # Socket blocking mode

    def __init__(self, host: str, port: int):
        """
        Initialize server with request handlers mapping and communication setup.

        Args:
            host: Host address to bind the server to (empty for all interfaces)
            port: Port number to listen on
        """
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.database = database.Database(Server.DATABASE_PATH)
        self.last_error = ""  # Last error description

        # Map request codes to their corresponding handler methods
        self.request_handlers: Dict[int, Callable] = {
            protocol.RequestCode.REGISTRATION.value: self._handle_registration,
            protocol.RequestCode.USERS_LIST.value: self._handle_users_list,
            protocol.RequestCode.PUBLIC_KEY.value: self._handle_public_key,
            protocol.RequestCode.SEND_MESSAGE.value: self._handle_message_send,
            protocol.RequestCode.PENDING_MESSAGES.value: self._handle_pending_messages,
        }

        # Configure logging
        logging_format = "[%(levelname)s - %(asctime)s]: %(message)s"
        logging.basicConfig(
            format=logging_format, level=logging.INFO, datefmt="%H:%M:%S"
        )

    def accept_connection(self, sock: socket.socket, mask: int) -> None:
        """
        Accept incoming client connection and register for read events.

        Args:
            sock: Server socket accepting connections
            mask: Event mask from selector
        """
        conn, address = sock.accept()
        conn.setblocking(Server.NON_BLOCKING)
        self.selector.register(conn, selectors.EVENT_READ, self.process_request)
        logging.debug(f"New connection accepted from {address}")

    def process_request(self, conn: socket.socket, mask: int) -> None:
        """
        Process client request by reading data and dispatching to appropriate handler.

        Args:
            conn: Client connection socket
            mask: Event mask from selector
        """
        client_addr = conn.getpeername() if hasattr(conn, "getpeername") else "Unknown"
        logging.info(f"Processing request from {client_addr}")

        try:
            data = conn.recv(Server.PACKET_SIZE)
            if data:
                request_header = protocol.RequestHeader()
                success = False

                if not request_header.unpack(data):
                    logging.error("Failed to parse request header")
                else:
                    # Invoke corresponding handler if request code is valid
                    if request_header.code in self.request_handlers:
                        handler = self.request_handlers[request_header.code]
                        success = handler(conn, data)
                    else:
                        logging.warning(f"Unknown request code: {request_header.code}")

                # Send generic error if request handling failed
                if not success:
                    response_header = protocol.ResponseHeader(
                        protocol.ResponseCode.ERROR.value
                    )
                    self.send_response(conn, response_header.pack())

                # Update client's last seen timestamp
                if hasattr(request_header, "clientID") and request_header.clientID:
                    self.database.set_last_seen(
                        request_header.clientID, str(datetime.now())
                    )
            else:
                logging.debug(
                    f"No data received from {client_addr}, closing connection"
                )
        except Exception as e:
            logging.error(f"Error processing request: {str(e)}")
        finally:
            # Always clean up the connection
            self.selector.unregister(conn)
            conn.close()

    def send_response(self, conn: socket.socket, data: bytes) -> bool:
        """
        Send response data to client with appropriate chunking.

        Args:
            conn: Client connection socket
            data: Response data to send

        Returns:
            True if sending was successful, False otherwise
        """
        size = len(data)
        sent = 0

        try:
            while sent < size:
                # Calculate chunk size for this iteration
                chunk_size = min(Server.PACKET_SIZE, size - sent)
                chunk = data[sent : sent + chunk_size]

                # Pad chunk to fill packet size if needed
                if len(chunk) < Server.PACKET_SIZE:
                    chunk += bytearray(Server.PACKET_SIZE - len(chunk))

                # Send the chunk
                bytes_sent = conn.send(chunk)
                if bytes_sent <= 0:
                    logging.error("Socket send returned unexpected result")
                    return False

                sent += bytes_sent

            logging.info(f"Response sent successfully ({size} bytes)")
            return True

        except Exception as e:
            client_addr = (
                conn.getpeername() if hasattr(conn, "getpeername") else "Unknown"
            )
            logging.error(f"Failed to send response to {client_addr}: {str(e)}")
            return False

    def start(self) -> bool:
        """
        Start the server, initialize database and begin listening for connections.

        Returns:
            True if server started successfully, False otherwise
        """
        # Initialize database
        if not self.database.initialize():
            self.last_error = "Failed to initialize database"
            return False

        # Setup the server socket
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(Server.MAX_CONNECTIONS)
            server_socket.setblocking(Server.NON_BLOCKING)

            # Register server socket with selector
            self.selector.register(
                server_socket, selectors.EVENT_READ, self.accept_connection
            )

        except Exception as e:
            self.last_error = str(e)
            logging.error(f"Failed to initialize server socket: {str(e)}")
            return False

        logging.info(f"Server started successfully on port {self.port}")
        print(f"MessageU server is listening for connections on port {self.port}...")

        # Main server loop
        try:
            while True:
                events = self.selector.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)

        except KeyboardInterrupt:
            logging.info("Server shutting down due to keyboard interrupt")
            return True
        except Exception as e:
            logging.exception(f"Unhandled exception in server main loop: {str(e)}")
            self.last_error = str(e)
            return False

    # Request handler methods
    def _handle_registration(self, conn: socket.socket, data: bytes) -> bool:
        """
        Process user registration request and create new user account.

        Args:
            conn: Client connection socket
            data: Request data

        Returns:
            True if registration was successful, False otherwise
        """
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()

        if not request.unpack(data):
            logging.error("Registration Request: Failed to parse request")
            return False

        try:
            # Validate username (alphanumeric only)
            if not request.name.isalnum():
                logging.info(
                    f"Registration Request: Invalid username format ({request.name})"
                )
                return False

            # Check if username already exists
            if self.database.client_username_exists(request.name):
                logging.info(
                    f"Registration Request: Username already exists ({request.name})"
                )
                return False

        except Exception as e:
            logging.error(f"Registration Request: Database error: {str(e)}")
            return False

        # Generate unique client ID and create client record
        client_id = uuid.uuid4().hex
        client = database.Client(
            client_id, request.name, request.publicKey, str(datetime.now())
        )

        # Store client in database
        if not self.database.store_client(client):
            logging.error(
                f"Registration Request: Failed to store client {request.name}"
            )
            return False

        # Prepare and send successful response
        logging.info(f"Successfully registered client: {request.name}")
        response.clientID = client.ID
        response.header.payloadSize = protocol.CLIENT_ID_LENGTH

        return self.send_response(conn, response.pack())

    def _handle_users_list(self, conn: socket.socket, data: bytes) -> bool:
        """
        Process request for users list and return all registered users.

        Args:
            conn: Client connection socket
            data: Request data

        Returns:
            True if request was handled successfully, False otherwise
        """
        request = protocol.RequestHeader()

        if not request.unpack(data):
            logging.error("Users list Request: Failed to parse request header")
            return False

        try:
            # Validate client ID
            if not self.database.client_id_exists(request.clientID):
                logging.info(f"Users list Request: Invalid client ID")
                return False

        except Exception as e:
            logging.error(f"Users list Request: Database error: {str(e)}")
            return False

        # Prepare response with users list
        response = protocol.ResponseHeader(protocol.ResponseCode.USERS_LIST.value)
        clients = self.database.get_clients_list()

        # Build payload with client IDs and names
        payload = b""
        for user in clients:
            if user[0] != request.clientID:  # Exclude requesting client
                payload += user[0]  # Client ID

                # Ensure name is properly null-terminated and padded
                name_bytes = user[1]
                if isinstance(name_bytes, str):
                    name_bytes = name_bytes.encode("utf-8")

                # Pad name to fixed size
                padded_name = name_bytes + b"\0" * (
                    protocol.NAME_SIZE - len(name_bytes)
                )
                payload += padded_name[: protocol.NAME_SIZE]  # Truncate if too long

        response.payloadSize = len(payload)
        logging.info(
            f"Sending clients list to client {request.clientID.hex() if isinstance(request.clientID, bytes) else request.clientID}"
        )

        return self.send_response(conn, response.pack() + payload)

    def _handle_public_key(self, conn: socket.socket, data: bytes) -> bool:
        """
        Process request for a user's public key.

        Args:
            conn: Client connection socket
            data: Request data

        Returns:
            True if request was handled successfully, False otherwise
        """
        request = protocol.PublicKeyRequest()
        response = protocol.PublicKeyResponse()

        if not request.unpack(data):
            logging.error("Public Key Request: Failed to parse request")
            return False

        # Retrieve requested client's public key
        public_key = self.database.get_client_public_key(request.clientID)
        if not public_key:
            logging.info(f"Public Key Request: Client ID not found")
            return False

        # Prepare and send response
        response.clientID = request.clientID
        response.publicKey = public_key
        response.header.payloadSize = (
            protocol.CLIENT_ID_LENGTH + protocol.PUBLIC_KEY_LENGTH
        )

        requesting_client = (
            request.header.clientID.hex()
            if isinstance(request.header.clientID, bytes)
            else request.header.clientID
        )
        target_client = (
            request.clientID.hex()
            if isinstance(request.clientID, bytes)
            else request.clientID
        )
        logging.info(
            f"Sending public key for client {target_client} to client {requesting_client}"
        )

        return self.send_response(conn, response.pack())

    def _handle_message_send(self, conn: socket.socket, data: bytes) -> bool:
        """
        Process request to send a message to another user.

        Args:
            conn: Client connection socket
            data: Request data

        Returns:
            True if message was stored successfully, False otherwise
        """
        request = protocol.MessageSendRequest()
        response = protocol.MessageSentResponse()

        if not request.unpack(conn, data):
            logging.error("Send Message Request: Failed to parse request")
            return False

        # Create message object
        message = database.Message(
            request.clientID,
            request.header.clientID,
            request.messageType,
            request.content,
        )

        # Store message in database
        message_id = self.database.store_message(message)
        if not message_id:
            logging.error("Send Message Request: Failed to store message")
            return False

        # Prepare and send response
        response.header.payloadSize = protocol.CLIENT_ID_LENGTH + protocol.MSG_ID_SIZE
        response.clientID = request.clientID
        response.messageID = message_id

        sender = (
            request.header.clientID.hex()
            if isinstance(request.header.clientID, bytes)
            else request.header.clientID
        )
        recipient = (
            request.clientID.hex()
            if isinstance(request.clientID, bytes)
            else request.clientID
        )
        logging.info(
            f"Message from {sender} to {recipient} stored successfully (ID: {message_id})"
        )

        return self.send_response(conn, response.pack())

    def _handle_pending_messages(self, conn: socket.socket, data: bytes) -> bool:
        """
        Process request for pending messages and deliver them to client.

        Args:
            conn: Client connection socket
            data: Request data

        Returns:
            True if request was handled successfully, False otherwise
        """
        request = protocol.RequestHeader()
        response = protocol.ResponseHeader(protocol.ResponseCode.PENDING_MESSAGES.value)

        if not request.unpack(data):
            logging.error("Pending messages request: Failed to parse request header")
            return False

        try:
            # Validate client ID
            if not self.database.client_id_exists(request.clientID):
                logging.info(f"Pending messages request: Invalid client ID")
                return False

        except Exception as e:
            logging.error(f"Pending messages request: Database error: {str(e)}")
            return False

        # Retrieve pending messages
        payload = b""
        messages = self.database.get_pending_messages(request.clientID)
        message_ids = []

        # Build payload with pending messages
        for msg in messages:  # id, from, type, content
            pending = protocol.PendingMessage()
            pending.messageID = int(msg[0])
            pending.MessageEngineID = msg[1]
            pending.messageType = int(msg[2])
            pending.content = msg[3]
            pending.messageSize = len(msg[3])
            message_ids.append(pending.messageID)

            # Add packed message to payload
            payload += pending.pack()

        # Set payload size in response header
        response.payloadSize = len(payload)
        client_id = (
            request.clientID.hex()
            if isinstance(request.clientID, bytes)
            else request.clientID
        )
        logging.info(f"Sending {len(messages)} pending messages to client {client_id}")

        # Send response and delete delivered messages on success
        if self.send_response(conn, response.pack() + payload):
            for msg_id in message_ids:
                self.database.remove_message(msg_id)
            return True

        return False