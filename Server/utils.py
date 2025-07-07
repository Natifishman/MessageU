"""
Author: Natanel Maor Fishman

utils.py: Utility functions for the MessageU server implementation.
Provides auxiliary methods for server management, logging configuration,
and system configuration handling.
"""

import logging
import sys
from typing import Optional


def terminate_server(error_message: str) -> None:
    """
    Terminates the server with an error message and appropriate exit code.
    Args: error_message: The error message to display before termination
    """
    logging.critical(f"FATAL ERROR: {error_message}")
    print(f"\nFATAL ERROR: {error_message}")
    print("MessageU Server is shutting down...")
    sys.exit(1)


def configure_logging(log_level: int = logging.INFO) -> None:
    """
    Configures the logging system with appropriate format and level.
    Args: log_level: The desired logging level (default: INFO)
    """
    log_format = "[%(levelname)s - %(asctime)s]: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    logging.basicConfig(format=log_format, level=log_level, datefmt=date_format)
    logging.info("Logging configuration initialized")


def read_port_from_file(filepath: str) -> Optional[int]:
    """
    Reads server port number from configuration file.

    Args:
        filepath: Path to the port configuration file

    Returns:
        Port number as integer if successful, None otherwise

    Notes:
        Only the first line of the file is considered.
        The line should contain just the port number.
    """
    try:
        with open(filepath, "r") as port_file:
            port_str = port_file.readline().strip()
            port = int(port_str)

            # Validate port number range
            if 1 <= port <= 65535:
                logging.info(f"Successfully read port {port} from {filepath}")
                return port
            else:
                logging.warning(f"Port {port} outside valid range (1-65535)")
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