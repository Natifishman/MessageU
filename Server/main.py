"""
MessageU Server - Main Entry Point
==================================

Author: Natanel Maor Fishman
Version: 2.0
Date: 2025

This module serves as the central control point for launching the
MessageU secure messaging server with appropriate error handling,
configuration management, and graceful shutdown capabilities.

The server provides secure messaging services with encryption,
user authentication, and message routing between clients.
"""

# ================================
# Standard Library Imports
# ================================

import os
import logging
import argparse
from typing import NoReturn, Optional

# ================================
# Application Imports
# ================================

import utils
import server

# ================================
# Constants
# ================================

DEFAULT_PORT = 1357
DEFAULT_CONFIG_FILE = "myport.info"

# ================================
# Function Definitions
# ================================


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for server configuration.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
        
    Details:
        Provides command-line interface for server configuration including
        port number, host address, and configuration file path.
        Arguments can override default settings and configuration file values.
    """
    parser = argparse.ArgumentParser(
        description="MessageU Secure Messaging Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Use default configuration
  python main.py --port 8080        # Use custom port
  python main.py --host 127.0.0.1   # Bind to specific interface
  python main.py --config custom.info  # Use custom config file
        """
    )
    
    parser.add_argument(
        "--port", 
        type=int, 
        help="Server port number (overrides config file)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="",
        help="Server hostname/IP (default: all interfaces)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_FILE,
        help="Path to port configuration file"
    )
    
    return parser.parse_args()


def determine_server_port(args: argparse.Namespace) -> int:
    """
    Determine the server port based on command-line arguments and configuration.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        int: Port number to use for the server
        
    Details:
        Port determination follows this priority:
        1. Command-line argument (--port)
        2. Configuration file value
        3. Default port (1357)
        
        Logs warnings when falling back to default values.
    """
    # Priority 1: Command-line argument
    if args.port is not None:
        logging.info(f"Using port from command-line argument: {args.port}")
        return args.port
    
    # Priority 2: Configuration file
    if os.path.exists(args.config):
        config_port = utils.read_port_from_file(args.config)
        if config_port is not None:
            logging.info(f"Using port from config file '{args.config}': {config_port}")
            return config_port
        else:
            logging.warning(f"Config file '{args.config}' exists but contains invalid port")
    else:
        logging.warning(f"Config file '{args.config}' not found")
    
    # Priority 3: Default port
    logging.warning(f"Using default port {DEFAULT_PORT}")
    return DEFAULT_PORT


def initialize_server(host: str, port: int) -> server.Server:
    """
    Initialize the MessageU server with specified configuration.
    
    Args:
        host: Host address to bind the server to
        port: Port number to listen on
        
    Returns:
        server.Server: Initialized server instance
        
    Raises:
        Exception: If server initialization fails
        
    Details:
        Creates and configures the server instance with proper
        error handling and logging. Validates configuration parameters.
    """
    try:
        message_server = server.Server(host, port)
        logging.info(f"Server initialized successfully")
        logging.info(f"  Host: {host if host else 'All interfaces'}")
        logging.info(f"  Port: {port}")
        return message_server
        
    except Exception as e:
        error_msg = f"Failed to initialize server: {str(e)}"
        logging.error(error_msg)
        raise Exception(error_msg)


def main() -> None:
    """
    Main entry point for the MessageU server.
    
    Handles configuration loading, server initialization, and execution.
    Provides graceful shutdown and comprehensive error handling.
    
    The function runs indefinitely until interrupted or an error occurs.
    
    Details:
        - Configures logging system
        - Parses command-line arguments
        - Determines server configuration
        - Initializes and starts server
        - Handles graceful shutdown on interruption
        - Provides detailed error reporting
    """
    # Configure logging first for proper error reporting
    utils.configure_logging()
    logging.info("Starting MessageU Server...")
    logging.info("=" * 50)

    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Determine server port with proper priority handling
        port = determine_server_port(args)
        
        # Initialize server with determined configuration
        message_server = initialize_server(args.host, port)
        
        # Start server main loop (this will block indefinitely)
        logging.info("Starting server main loop...")
        if not message_server.start():
            error_msg = f"Server failed to start: {message_server.last_error}"
            utils.terminate_server(error_msg)
            
    except KeyboardInterrupt:
        # Graceful shutdown on keyboard interrupt
        logging.info("Server shutdown requested (keyboard interrupt)")
        print("\nServer shutdown requested. Goodbye!")
        return
        
    except Exception as e:
        # Handle any unhandled exceptions
        error_msg = f"Unhandled exception: {str(e)}"
        utils.terminate_server(error_msg)


# ================================
# Entry Point
# ================================

if __name__ == "__main__":
    main()