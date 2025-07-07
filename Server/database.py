"""
MessageU Server - Database Management Module
============================================

Author: Natanel Maor Fishman
Version: 2.0
Date: 2025

Database management module for the MessageU messaging platform.
Implements persistence, user account management, and message storage with
comprehensive data validation and error handling.

This module provides an abstraction layer over the SQLite database,
offering a clean interface for storing and retrieving user and message data.
Features include client registration, message storage, and secure data access.
"""

# ================================
# Standard Library Imports
# ================================

import logging
import sqlite3
from typing import List, Tuple, Optional, Any, Union
from contextlib import contextmanager

# ================================
# Application Imports
# ================================

import protocol

# ================================
# Constants
# ================================

# Table names
CLIENTS_TABLE = "clients"
MESSAGES_TABLE = "messages"

# SQL statements for table creation
CREATE_CLIENTS_TABLE = f"""
    CREATE TABLE IF NOT EXISTS {CLIENTS_TABLE} (
        ID BLOB(16) NOT NULL PRIMARY KEY,
        Name BLOB(255) NOT NULL,
        PublicKey BLOB(160) NOT NULL,
        LastSeen TEXT NOT NULL
    );
"""

CREATE_MESSAGES_TABLE = f"""
    CREATE TABLE IF NOT EXISTS {MESSAGES_TABLE} (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        ToClient BLOB(16) NOT NULL,
        FromClient BLOB(16) NOT NULL,
        Type INTEGER NOT NULL,
        Content BLOB,
        FOREIGN KEY(ToClient) REFERENCES {CLIENTS_TABLE}(ID),
        FOREIGN KEY(FromClient) REFERENCES {CLIENTS_TABLE}(ID)
    );
"""

# ================================
# Data Model Classes
# ================================


class Client:
    """
    Represents a registered client in the MessageU system.
    
    Contains identification information and authentication data including
    unique client ID, username, public key, and last activity timestamp.
    
    Features:
        - Data validation according to protocol specifications
        - Flexible input handling (string/bytes)
        - Comprehensive error checking
    """

    def __init__(
        self, cid: str, cname: Union[str, bytes], public_key: bytes, last_seen: str
    ):
        """
        Initialize a client record with required fields.

        Args:
            cid: Unique client identifier (16 bytes as hex string)
            cname: Client's username (ASCII string, max 255 bytes)
            public_key: Client's public RSA key (160 bytes)
            last_seen: Timestamp of client's last interaction with server
            
        Details:
            Converts client ID from hex string to bytes if necessary.
            Handles username as either string or bytes format.
            Validates all input parameters according to protocol specifications.
        """
        # Convert client ID to bytes if provided as hex string
        self.ID = bytes.fromhex(cid) if isinstance(cid, str) else cid

        # Handle name as either string or bytes
        if isinstance(cname, str):
            self.Name = cname.encode("utf-8")
        else:
            self.Name = cname

        self.PublicKey = public_key
        self.LastSeen = last_seen

    def validate(self) -> bool:
        """
        Validate client attributes according to protocol specifications.

        Returns:
            True if all attributes are valid, False otherwise
            
        Details:
            Performs comprehensive validation of all client attributes:
            - Client ID length (16 bytes)
            - Username length (max 255 bytes)
            - Public key length (160 bytes)
            - Last seen timestamp presence
        """
        # Check ID
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_LENGTH:
            logging.error(f"Invalid client ID length: {len(self.ID) if self.ID else 0}")
            return False

        # Check Name
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            logging.error(
                f"Invalid client name length: {len(self.Name) if self.Name else 0}"
            )
            return False

        # Check PublicKey
        if not self.PublicKey or len(self.PublicKey) != protocol.PUBLIC_KEY_LENGTH:
            logging.error(
                f"Invalid public key length: {len(self.PublicKey) if self.PublicKey else 0}"
            )
            return False

        # Check LastSeen
        if not self.LastSeen:
            logging.error("Missing last seen timestamp")
            return False

        return True


class Message:
    """
    Represents a message exchanged between clients in the MessageU system.
    
    Contains message metadata and encrypted content including sender/recipient
    information, message type, and encrypted payload.
    
    Features:
        - Message type validation
        - Client ID validation
        - Flexible content handling
        - Database integration support
    """

    def __init__(
        self, to_client: bytes, from_client: bytes, mtype: int, content: bytes
    ):
        """
        Initialize a message record with required fields.

        Args:
            to_client: Recipient's unique ID (16 bytes)
            from_client: Sender's unique ID (16 bytes)
            mtype: Message type identifier (1 byte)
            content: Encrypted message content (variable length)
            
        Details:
            Creates a new message record with validated parameters.
            Message ID is assigned by the database upon storage.
        """
        self.ID = 0  # Message ID, assigned by database
        self.ToClient = to_client
        self.FromClient = from_client
        self.Type = mtype
        self.Content = content

    def validate(self) -> bool:
        """
        Validate message attributes according to protocol specifications.

        Returns:
            True if all attributes are valid, False otherwise
            
        Details:
            Performs comprehensive validation of all message attributes:
            - Recipient and sender ID lengths (16 bytes each)
            - Message type range validation
            - Content format validation
        """
        # Check ToClient
        if not self.ToClient or len(self.ToClient) != protocol.CLIENT_ID_LENGTH:
            logging.error(
                f"Invalid recipient ID length: {len(self.ToClient) if self.ToClient else 0}"
            )
            return False

        # Check FromClient
        if not self.FromClient or len(self.FromClient) != protocol.CLIENT_ID_LENGTH:
            logging.error(
                f"Invalid sender ID length: {len(self.FromClient) if self.FromClient else 0}"
            )
            return False

        # Check Type
        if self.Type is None or self.Type > protocol.MSG_TYPE_MAX:
            logging.error(f"Invalid message type: {self.Type}")
            return False

        # Content can be empty but must be bytes
        if self.Content is None:
            logging.warning("Message has empty content")

        return True


# ================================
# Database Management Class
# ================================


class Database:
    """
    Database management class for the MessageU server.
    
    Provides methods for storing and retrieving clients and messages with
    comprehensive error handling and data validation. Uses SQLite as the
    underlying database engine with proper connection management.
    
    Features:
        - Client registration and management
        - Message storage and retrieval
        - Data validation and integrity checks
        - Connection pooling and error handling
        - Foreign key relationships
    """

    def __init__(self, db_path: str):
        """
        Initialize database connection parameters.

        Args:
            db_path: Path to SQLite database file
            
        Details:
            Sets up database connection parameters. The actual database
            connection is established when needed using the context manager.
        """
        self.db_path = db_path

    # ================================
    # Connection Management
    # ================================

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Ensures connections are properly closed even if exceptions occur.
        Provides automatic cleanup and error handling for database operations.
        
        Yields:
            SQLite connection object
            
        Raises:
            sqlite3.Error: If connection cannot be established
            
        Example:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM clients")
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.text_factory = bytes
            yield conn
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()

    # ================================
    # Database Initialization
    # ================================

    def initialize(self) -> bool:
        """
        Initialize database tables and schema.
        
        Returns:
            True if initialization successful, False otherwise
            
        Details:
            Creates the necessary database tables if they don't exist.
            Sets up proper schema with foreign key relationships and
            appropriate data types for secure message storage.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create clients table
                cursor.execute(CREATE_CLIENTS_TABLE)
                
                # Create messages table
                cursor.execute(CREATE_MESSAGES_TABLE)
                
                conn.commit()
                logging.info("Database initialized successfully")
                return True
                
        except sqlite3.Error as e:
            logging.error(f"Database initialization failed: {str(e)}")
            return False

    # ================================
    # Client Management Methods
    # ================================

    def client_username_exists(self, username: str) -> bool:
        """
        Check if a username already exists in the database.
        
        Args:
            username: Username to check
            
        Returns:
            True if username exists, False otherwise
            
        Details:
            Performs case-sensitive username lookup in the database.
            Used during client registration to prevent duplicate usernames.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {CLIENTS_TABLE} WHERE Name = ?",
                    (username.encode("utf-8"),)
                )
                count = cursor.fetchone()[0]
                return count > 0
                
        except sqlite3.Error as e:
            logging.error(f"Error checking username existence: {str(e)}")
            return False

    def client_id_exists(self, client_id: bytes) -> bool:
        """
        Check if a client ID exists in the database.
        
        Args:
            client_id: Client ID to check
            
        Returns:
            True if client ID exists, False otherwise
            
        Details:
            Validates client ID format and checks existence in database.
            Used for authentication and message routing validation.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,)
                )
                count = cursor.fetchone()[0]
                return count > 0
                
        except sqlite3.Error as e:
            logging.error(f"Error checking client ID existence: {str(e)}")
            return False

    def store_client(self, client: Client) -> bool:
        """
        Store a new client in the database.
        
        Args:
            client: Client object to store
            
        Returns:
            True if storage successful, False otherwise
            
        Details:
            Validates client data and stores it in the database.
            Performs duplicate checking and data integrity validation.
        """
        if not client.validate():
            logging.error("Invalid client data")
            return False

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO {CLIENTS_TABLE} (ID, Name, PublicKey, LastSeen) VALUES (?, ?, ?, ?)",
                    (client.ID, client.Name, client.PublicKey, client.LastSeen)
                )
                conn.commit()
                logging.info(f"Client stored successfully: {client.Name.decode('utf-8', errors='ignore')}")
                return True
                
        except sqlite3.IntegrityError:
            logging.error("Client ID already exists")
            return False
        except sqlite3.Error as e:
            logging.error(f"Error storing client: {str(e)}")
            return False

    # ================================
    # Message Management Methods
    # ================================

    def store_message(self, msg: Message) -> Optional[int]:
        """
        Store a new message in the database.
        
        Args:
            msg: Message object to store
            
        Returns:
            Message ID if storage successful, None otherwise
            
        Details:
            Validates message data and stores it in the database.
            Returns the assigned message ID for tracking purposes.
        """
        if not msg.validate():
            logging.error("Invalid message data")
            return None

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO {MESSAGES_TABLE} (ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
                    (msg.ToClient, msg.FromClient, msg.Type, msg.Content)
                )
                message_id = cursor.lastrowid
                conn.commit()
                logging.info(f"Message stored successfully with ID: {message_id}")
                return message_id
                
        except sqlite3.Error as e:
            logging.error(f"Error storing message: {str(e)}")
            return None

    def remove_message(self, msg_id: int) -> bool:
        """
        Remove a message from the database.
        
        Args:
            msg_id: ID of message to remove
            
        Returns:
            True if removal successful, False otherwise
            
        Details:
            Deletes a specific message by ID. Used after successful
            message delivery to clean up the pending messages queue.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"DELETE FROM {MESSAGES_TABLE} WHERE ID = ?",
                    (msg_id,)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logging.info(f"Message {msg_id} removed successfully")
                    return True
                else:
                    logging.warning(f"Message {msg_id} not found")
                    return False
                    
        except sqlite3.Error as e:
            logging.error(f"Error removing message: {str(e)}")
            return False

    # ================================
    # Data Retrieval Methods
    # ================================

    def set_last_seen(self, client_id: bytes, timestamp: str) -> bool:
        """
        Update client's last seen timestamp.
        
        Args:
            client_id: Client ID to update
            timestamp: New timestamp string
            
        Returns:
            True if update successful, False otherwise
            
        Details:
            Updates the last activity timestamp for a client.
            Used to track client activity and connection status.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"UPDATE {CLIENTS_TABLE} SET LastSeen = ? WHERE ID = ?",
                    (timestamp, client_id)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logging.debug(f"Updated last seen for client {client_id.hex()}")
                    return True
                else:
                    logging.warning(f"Client {client_id.hex()} not found for last seen update")
                    return False
                    
        except sqlite3.Error as e:
            logging.error(f"Error updating last seen: {str(e)}")
            return False

    def get_clients_list(self) -> List[Tuple[bytes, bytes]]:
        """
        Get list of all registered clients.
        
        Returns:
            List of tuples containing (client_id, username) pairs
            
        Details:
            Retrieves all registered clients from the database.
            Returns client IDs and usernames for client discovery.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT ID, Name FROM {CLIENTS_TABLE}")
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logging.error(f"Error retrieving clients list: {str(e)}")
            return []

    def get_client_public_key(self, client_id: bytes) -> Optional[bytes]:
        """
        Get public key for a specific client.
        
        Args:
            client_id: Client ID to retrieve key for
            
        Returns:
            Public key bytes if found, None otherwise
            
        Details:
            Retrieves the public key for secure communication setup.
            Used for message encryption and key exchange.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT PublicKey FROM {CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,)
                )
                result = cursor.fetchone()
                return result[0] if result else None
                
        except sqlite3.Error as e:
            logging.error(f"Error retrieving public key: {str(e)}")
            return None

    def get_pending_messages(
        self, client_id: bytes
    ) -> List[Tuple[int, bytes, int, bytes]]:
        """
        Get pending messages for a specific client.
        
        Args:
            client_id: Client ID to retrieve messages for
            
        Returns:
            List of tuples containing (message_id, sender_id, message_type, content)
            
        Details:
            Retrieves all pending messages for a client.
            Messages are returned in order of receipt for processing.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT ID, FromClient, Type, Content FROM {MESSAGES_TABLE} WHERE ToClient = ?",
                    (client_id,)
                )
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            logging.error(f"Error retrieving pending messages: {str(e)}")
            return []

    def get_client_by_id(self, client_id: bytes) -> Optional[Client]:
        """
        Get complete client information by ID.
        
        Args:
            client_id: Client ID to retrieve
            
        Returns:
            Client object if found, None otherwise
            
        Details:
            Retrieves complete client information including all fields.
            Used for client validation and information retrieval.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT ID, Name, PublicKey, LastSeen FROM {CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,)
                )
                result = cursor.fetchone()
                
                if result:
                    return Client(
                        result[0].hex(),  # ID as hex string
                        result[1],        # Name
                        result[2],        # PublicKey
                        result[3].decode('utf-8') if isinstance(result[3], bytes) else result[3]  # LastSeen
                    )
                return None
                
        except sqlite3.Error as e:
            logging.error(f"Error retrieving client: {str(e)}")
            return None

    def get_message_count(self, client_id: bytes) -> int:
        """
        Get count of pending messages for a client.
        
        Args:
            client_id: Client ID to count messages for
            
        Returns:
            Number of pending messages
            
        Details:
            Returns the count of pending messages for efficient
            message queue management and status reporting.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {MESSAGES_TABLE} WHERE ToClient = ?",
                    (client_id,)
                )
                return cursor.fetchone()[0]
                
        except sqlite3.Error as e:
            logging.error(f"Error counting messages: {str(e)}")
            return 0