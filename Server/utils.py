"""
MessageU Server - Utility Functions
===================================

Author: Natanel Maor Fishman
Version: 2.0
Date: 2025

Utility functions for the MessageU server implementation.
Provides auxiliary methods for server management, logging configuration,
and system configuration handling.

This module contains helper functions that support the main server
functionality including logging setup, configuration file handling,
and error management.
"""

# ================================
# Standard Library Imports
# ================================

import logging
import sys
from typing import Optional

# ================================
# Constants
# ================================

# Port validation constants
MIN_PORT = 1
MAX_PORT = 65535

# Logging configuration
DEFAULT_LOG_LEVEL = logging.INFO
LOG_FORMAT = "[%(levelname)s - %(asctime)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ================================
# Function Definitions
# ================================


def configure_logging(log_level: int = DEFAULT_LOG_LEVEL) -> None:
    """
    Configures the logging system with appropriate format and level.
    
    Args:
        log_level: The desired logging level (default: INFO)
        
    Details:
        Sets up the logging system with a standardized format that includes
        timestamp, log level, and message. Configures both console output
        and file logging capabilities.
        
    Example:
        configure_logging(logging.DEBUG)  # Enable debug logging
    """
    logging.basicConfig(
        format=LOG_FORMAT, 
        level=log_level, 
        datefmt=DATE_FORMAT
    )
    logging.info("Logging configuration initialized")


def read_port_from_file(filepath: str) -> Optional[int]:
    """
    Reads server port number from configuration file.

    Args:
        filepath: Path to the port configuration file

    Returns:
        Port number as integer if successful, None otherwise

    Details:
        Reads the port number from the first line of the specified file.
        Validates that the port is within the valid range (1-65535).
        Provides comprehensive error handling for various file access issues.
        
    Notes:
        - Only the first line of the file is considered
        - The line should contain just the port number
        - Invalid ports or file errors return None
        
    Example:
        port = read_port_from_file("myport.info")
        if port:
            print(f"Using port {port}")
        else:
            print("Failed to read port from file")
    """
    try:
        with open(filepath, "r") as port_file:
            port_str = port_file.readline().strip()
            port = int(port_str)

            # Validate port number range
            if MIN_PORT <= port <= MAX_PORT:
                logging.info(f"Successfully read port {port} from {filepath}")
                return port
            else:
                logging.warning(f"Port {port} outside valid range ({MIN_PORT}-{MAX_PORT})")
                return None

    except FileNotFoundError:
        logging.warning(f"Configuration file not found: {filepath}")
        return None
    except ValueError:
        logging.warning(f"Invalid port number in {filepath}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error reading port file: {str(e)}")
        return None


def terminate_server(error_message: str) -> None:
    """
    Terminates the server with an error message and appropriate exit code.
    
    Args:
        error_message: The error message to display before termination
        
    Details:
        Logs the critical error, displays user-friendly error message,
        and terminates the server process with exit code 1.
        Ensures proper cleanup and error reporting before shutdown.
        
    Example:
        if critical_error:
            terminate_server("Database connection failed")
    """
    logging.critical(f"FATAL ERROR: {error_message}")
    print(f"\nFATAL ERROR: {error_message}")
    print("MessageU Server is shutting down...")
    sys.exit(1)