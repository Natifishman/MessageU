"""
Author: Natanel Maor Fishman

database.py: Database management module for the MessageU messaging platform.
Implements persistence, user account management, and message storage with
comprehensive data validation and error handling.

This module provides an abstraction layer over the SQLite database,
offering a clean interface for storing and retrieving user and message data.
"""

import logging
import sqlite3
import protocol
from typing import List, Tuple, Optional, Any, Union
from contextlib import contextmanager


class Client:
    """
    Represents a registered client in the MessageU system.
    Contains identification information and authentication data.
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
        """
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
    Contains message metadata and encrypted content.
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


class Database:
    """
    Database management class for the MessageU server.
    Provides methods for storing and retrieving clients and messages.
    """

    # Table names
    CLIENTS_TABLE = "clients"
    MESSAGES_TABLE = "messages"

    # SQL statements
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

    def __init__(self, db_path: str):
        """
        Initialize database connection parameters.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures connections are properly closed even if exceptions occur.

        Yields:
            SQLite connection object
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

    def initialize(self) -> bool:
        """
        Initialize database schema by creating necessary tables.

        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                # Create tables if they don't exist
                conn.executescript(self.CREATE_CLIENTS_TABLE)
                conn.executescript(self.CREATE_MESSAGES_TABLE)

                # Create indexes for performance
                conn.executescript(
                    f"CREATE INDEX IF NOT EXISTS idx_messages_to ON {self.MESSAGES_TABLE}(ToClient);"
                )
                conn.executescript(
                    f"CREATE INDEX IF NOT EXISTS idx_clients_name ON {self.CLIENTS_TABLE}(Name);"
                )

            logging.info("Database initialized successfully")
            return True
        except Exception as e:
            logging.error(f"Failed to initialize database: {str(e)}")
            return False

    def client_username_exists(self, username: str) -> bool:
        """
        Check if a username already exists in the database.

        Args:
            username: Client username to check

        Returns:
            True if username exists, False otherwise
        """
        try:
            username_bytes = (
                username.encode("utf-8") if isinstance(username, str) else username
            )

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {self.CLIENTS_TABLE} WHERE Name = ?",
                    (username_bytes,),
                )
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            logging.error(f"Error checking username existence: {str(e)}")
            raise

    def client_id_exists(self, client_id: bytes) -> bool:
        """
        Check if a client ID already exists in the database.

        Args:
            client_id: Client ID to check

        Returns:
            True if client ID exists, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {self.CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,),
                )
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            logging.error(f"Error checking client ID existence: {str(e)}")
            raise

    def store_client(self, client: Client) -> bool:
        """
        Store a new client in the database.

        Args:
            client: Client object to store

        Returns:
            True if client was stored successfully, False otherwise
        """
        if not isinstance(client, Client) or not client.validate():
            logging.error("Invalid client object")
            return False

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO {self.CLIENTS_TABLE} VALUES (?, ?, ?, ?)",
                    (client.ID, client.Name, client.PublicKey, client.LastSeen),
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            logging.error("Client already exists or constraint violation")
            return False
        except Exception as e:
            logging.error(f"Error storing client: {str(e)}")
            return False

    def store_message(self, msg: Message) -> Optional[int]:
        """
        Store a new message in the database.

        Args:
            msg: Message object to store

        Returns:
            Message ID if stored successfully, None otherwise
        """
        if not isinstance(msg, Message) or not msg.validate():
            logging.error("Invalid message object")
            return None

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO {self.MESSAGES_TABLE} (ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
                    (msg.ToClient, msg.FromClient, msg.Type, msg.Content),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logging.error(f"Error storing message: {str(e)}")
            return None

    def remove_message(self, msg_id: int) -> bool:
        """
        Remove a message from the database by ID.

        Args:
            msg_id: ID of message to remove

        Returns:
            True if message was removed successfully, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"DELETE FROM {self.MESSAGES_TABLE} WHERE ID = ?", (msg_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logging.error(f"Error removing message {msg_id}: {str(e)}")
            return False

    def set_last_seen(self, client_id: bytes, timestamp: str) -> bool:
        """
        Update the last seen timestamp for a client.

        Args:
            client_id: ID of client to update
            timestamp: New timestamp value

        Returns:
            True if update was successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"UPDATE {self.CLIENTS_TABLE} SET LastSeen = ? WHERE ID = ?",
                    (timestamp, client_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logging.error(f"Error updating last seen timestamp: {str(e)}")
            return False

    def get_clients_list(self) -> List[Tuple[bytes, bytes]]:
        """
        Retrieve a list of all registered clients.

        Returns:
            List of tuples containing client ID and name
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT ID, Name FROM {self.CLIENTS_TABLE}")
                return cursor.fetchall()
        except Exception as e:
            logging.error(f"Error retrieving clients list: {str(e)}")
            return []

    def get_client_public_key(self, client_id: bytes) -> Optional[bytes]:
        """
        Retrieve the public key for a specific client.

        Args:
            client_id: ID of client to retrieve key for

        Returns:
            Public key bytes if found, None otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT PublicKey FROM {self.CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,),
                )
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logging.error(f"Error retrieving public key: {str(e)}")
            return None

    def get_pending_messages(
        self, client_id: bytes
    ) -> List[Tuple[int, bytes, int, bytes]]:
        """
        Retrieve all pending messages for a specific client.

        Args:
            client_id: ID of client to retrieve messages for

        Returns:
            List of tuples containing message ID, sender ID, message type, and content
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT ID, FromClient, Type, Content FROM {self.MESSAGES_TABLE} WHERE ToClient = ?",
                    (client_id,),
                )
                return cursor.fetchall()
        except Exception as e:
            logging.error(f"Error retrieving pending messages: {str(e)}")
            return []

    def get_client_by_id(self, client_id: bytes) -> Optional[Client]:
        """
        Retrieve complete client information by ID.

        Args:
            client_id: ID of client to retrieve

        Returns:
            Client object if found, None otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT ID, Name, PublicKey, LastSeen FROM {self.CLIENTS_TABLE} WHERE ID = ?",
                    (client_id,),
                )
                result = cursor.fetchone()
                if not result:
                    return None

                # Convert ID from bytes to hex string for Client constructor
                id_hex = result[0].hex()
                return Client(id_hex, result[1], result[2], result[3])
        except Exception as e:
            logging.error(f"Error retrieving client by ID: {str(e)}")
            return None

    def get_message_count(self, client_id: bytes) -> int:
        """
        Count pending messages for a specific client.

        Args:
            client_id: ID of client to count messages for

        Returns:
            Number of pending messages
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {self.MESSAGES_TABLE} WHERE ToClient = ?",
                    (client_id,),
                )
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            logging.error(f"Error counting pending messages: {str(e)}")
            return 0