/**
 * @file        ConsoleInterface.h
 * @author      Natanel Fishman
 * @brief       interactive console interface for secure messaging client
 * @details     Provides command-line interface for MessageU client with
 *              user authentication, menu management, and secure messaging operations
 * @date        2025
 */

#pragma once

#include "MessageEngine.h"
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <utility>
#include <cstdint>

 /**
  * @class       ConsoleInterface
  * @brief       Advanced interactive console interface for secure messaging client
  * @details     Provides comprehensive command-line interface with user authentication,
  *              menu management, input validation, and secure messaging operations.
  *              Features intuitive user experience with clear feedback and error handling.
  *
  * @note        This class is non-copyable to prevent interface state conflicts
  *              and ensure proper resource management.
  */
class ConsoleInterface
{
public:
	/**
	 * @brief       Default constructor - initializes console interface
	 * @details     Creates new console interface with unauthenticated state
	 */
	ConsoleInterface() : authenticated(false) {}

	/**
	 * @brief       Default destructor with automatic cleanup
	 * @details     Ensures proper cleanup of interface resources
	 */
	~ConsoleInterface() = default;

	/**
	 * @brief       Prepares the client interface and establishes connections
	 * @details     Loads server configuration and user credentials for operation
	 */
	void prepare();

	/**
	 * @brief       Displays the main application menu with user context
	 * @details     Renders personalized greeting and available commands based on
	 *              authentication status
	 */
	void showMenu() const;

	/**
	 * @brief       Processes user command input and executes selected operation
	 * @details     Captures user input, validates selection, and executes corresponding
	 *              command with comprehensive error handling
	 */
	void processCommand();

	/**
	 * @brief       Waits for user acknowledgment before continuing
	 * @details     Pauses execution until user provides input
	 */
	void waitForInput() const { system("pause"); }

	/**
	 * @brief       Clears the console screen for improved user experience
	 * @details     Provides clean interface by clearing previous output
	 */
	void clearScreen() const { system("cls"); }

	// Explicitly delete copy operations to prevent interface state conflicts
	ConsoleInterface(const ConsoleInterface&) = delete;
	ConsoleInterface& operator=(const ConsoleInterface&) = delete;

private:
	/**
	 * @class       MenuCommands
	 * @brief       Menu command structure with metadata and validation
	 * @details     Encapsulates command information including type, authentication
	 *              requirements, display labels, and confirmation messages
	 */
	class MenuCommands
	{
	public:
		/**
		 * @enum         CommandsEnum
		 * @brief        Available menu commands with unique identifiers
		 * @details      Each command corresponds to specific client functionality
		 */
		enum class CommandsEnum : uint32_t
		{
			CREATE_ACCOUNT = 110,           ///< Register new user account
			FETCH_USER_LIST = 120,          ///< Retrieve list of registered users
			FETCH_PUBLIC_KEY = 130,         ///< Get public key of specific user
			CHECK_INBOX = 140,              ///< Retrieve pending messages
			COMPOSE_MESSAGE = 150,          ///< Send encrypted text message
			REQUEST_ENCRYPTION_KEY = 151,   ///< Request symmetric key from user
			SHARE_ENCRYPTION_KEY = 152,     ///< Share symmetric key with user
			UPLOAD_FILE = 153,              ///< Send encrypted file
			QUIT = 0                        ///< Exit application
		};

	private:
		bool _requiresAuthentication;       ///< Whether command requires user authentication
		CommandsEnum _commandType;          ///< Command identifier
		std::string _confirmationMessage;   ///< Success confirmation message
		std::string _displayLabel;          ///< User-facing command description

	public:
		/**
		 * @brief       Default constructor initializes command to quit
		 * @details     Creates command with default values for safe initialization
		 */
		MenuCommands() : _commandType(CommandsEnum::QUIT), _requiresAuthentication(false) {}

		/**
		 * @brief       Full constructor with complete command metadata
		 * @param[in]   commandValue    Command type identifier
		 * @param[in]   authRequired    Whether authentication is required
		 * @param[in]   description     User-facing command description
		 * @param[in]   confirmation    Success confirmation message
		 * @details     Creates command with all necessary metadata for display and execution
		 */
		MenuCommands(const CommandsEnum commandValue, const bool authRequired,
			std::string description, std::string confirmation)
			: _commandType(commandValue), _requiresAuthentication(authRequired),
			_displayLabel(std::move(description)), _confirmationMessage(std::move(confirmation)) {
		}

		/**
		 * @brief       Stream insertion operator for command display
		 * @param[in,out] outputStream    Output stream for command display
		 * @param[in]     command         Command to display
		 * @return      Reference to output stream
		 * @details     Formats command for display in menu format "ID) Description"
		 */
		friend std::ostream& operator<<(std::ostream& outputStream, const MenuCommands& command) {
			outputStream << std::setw(2) << static_cast<uint32_t>(command._commandType)
				<< ") " << command._displayLabel;
			return outputStream;
		}

		// Accessor methods for command properties
		CommandsEnum getType() const { return _commandType; }
		bool requiresAuthentication() const { return _requiresAuthentication; }
		std::string getConfirmationMessage() const { return _confirmationMessage; }
	};

private:
	bool authenticated;                     ///< Current user authentication status
	MessageEngine engineInstance;           ///< Secure messaging engine instance

	/**
	 * @brief       Terminates application with error notification
	 * @param[in]   errorMessage    Error message to display before termination
	 * @details     Displays critical error and exits application gracefully
	 */
	void terminateWithError(const std::string& errorMessage) const;

	/**
	 * @brief       Captures and validates user text input
	 * @param[in]   promptMessage    Optional prompt message for user
	 * @return      Validated user input string
	 * @details     Ensures non-empty input with comprehensive error handling
	 */
	std::string captureInput(const std::string& promptMessage = "") const;

	/**
	 * @brief       Validates user command selection against available options
	 * @param[out]  selectedCommand    Validated command if selection is successful
	 * @return      true if valid command selected, false otherwise
	 * @details     Converts user input to valid command with error handling
	 */
	bool validateCommandSelection(MenuCommands& selectedCommand) const;

	/**
	 * @brief       Executes the selected command and returns operation result
	 * @param[in]   command    Command to execute
	 * @return      true if command executed successfully, false otherwise
	 * @details     Handles all command types with appropriate user interaction
	 */
	bool executeSelectedCommand(const MenuCommands& command);

	/**
	 * @brief       Displays received messages in formatted output
	 * @param[in]   messages    Vector of messages to display
	 * @details     Formats and displays message content with sender information
	 */
	void displayMessages(const std::vector<MessageEngine::MessageData>& messages) const;

	/**
	 * @brief       Displays list of registered users
	 * @details     Shows all available users in formatted list
	 */
	void displayUserList() const;

	// Available user commands with complete metadata
	const std::vector<MenuCommands> _availableCommands{
		{ MenuCommands::CommandsEnum::CREATE_ACCOUNT,			false, "Register", "Account successfully created."},
		{ MenuCommands::CommandsEnum::FETCH_USER_LIST,			true,  "Request for client list", ""},
		{ MenuCommands::CommandsEnum::FETCH_PUBLIC_KEY,			true,  "Request for public key", "Public key retrieved successfully."},
		{ MenuCommands::CommandsEnum::CHECK_INBOX,				true,  "Request for waiting messages", ""},
		{ MenuCommands::CommandsEnum::COMPOSE_MESSAGE,			true,  "Send a text message", "Message delivered successfully."},
		{ MenuCommands::CommandsEnum::REQUEST_ENCRYPTION_KEY,   true,  "Send a request for symmetric key", "Symmetric key request sent successfully."},
		{ MenuCommands::CommandsEnum::SHARE_ENCRYPTION_KEY,		true,  "Send your symmetric key", "Symmetric key shared successfully."},
		{ MenuCommands::CommandsEnum::UPLOAD_FILE,				true,  "Send a file", "File transferred successfully."},
		{ MenuCommands::CommandsEnum::QUIT,						false, "Exit client", ""}
	};
};