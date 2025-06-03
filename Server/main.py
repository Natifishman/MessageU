"""
Author: Natanel Maor Fishman

main.py: Entry point of MessageU Server.
Initializes server components, handles configuration loading,
and orchestrates the main execution flow.

This module serves as the central control point for launching the
MessageU secure messaging server with appropriate error handling.
"""

import os
import logging
import argparse
from typing import NoReturn

import utils
import server


def parse_arguments():
    """Parse command-line arguments for server configuration"""
    parser = argparse.ArgumentParser(description="MessageU Secure Messaging Server")
    parser.add_argument(
        "--port", type=int, help="Server port number (overrides config file)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="",
        help="Server hostname/IP (default: all interfaces)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="myport.info",
        help="Path to port configuration file",
    )
    return parser.parse_args()


def main() -> NoReturn:
    """
    Main entry point for the MessageU server.
    Handles configuration loading, server initialization, and execution.
    """
    # Constants
    DEFAULT_PORT = 1357

    # Configure logging first
    utils.configure_logging()
    logging.info("Starting MessageU Server...")

    # Parse command-line arguments
    args = parse_arguments()

    # Determine server port (priority: command-line > config file > default)
    port = args.port
    if port is None:
        # Try reading from config file
        if os.path.exists(args.config):
            port = utils.read_port_from_file(args.config)

        # If still no valid port, use default
        if port is None:
            logging.warning(f"Using default port {DEFAULT_PORT}")
            port = DEFAULT_PORT

    # Create and initialize server
    try:
        message_server = server.Server(args.host, port)
        logging.info(f"Server initialized with port {port}")

        # Start server main loop (this will block indefinitely)
        if not message_server.start():
            utils.terminate_server(f"Server failed to start: {message_server.lastErr}")

    except KeyboardInterrupt:
        logging.info("Server shutdown requested (keyboard interrupt)")
        print("\nServer shutdown requested. Goodbye!")
        return
    except Exception as e:
        utils.terminate_server(f"Unhandled exception: {str(e)}")


if __name__ == "__main__":
    main()