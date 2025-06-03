/**
 * @author	Natanel Fishman
 * @file	ConsoleInterface.h
 * @brief	Client's interface for user input.
 */
#pragma once

#include "MessageEngine.h"
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <utility>
#include <cstdint>

// Provides an interactive terminal interface for the messaging client
class ConsoleInterface
{
public:
	ConsoleInterface() : authenticated(false) {} // Default constructor
	~ConsoleInterface() = default; 	// Destructor ensures proper cleanup

	// Prevent copying and assignment
	ConsoleInterface(const ConsoleInterface&) = delete;
	ConsoleInterface& operator=(const ConsoleInterface&) = delete;
	
	// Main client interface functions
	void prepare();
	void showMenu() const;
	void processCommand();

	// Utility functions
	void waitForInput() const { system("pause"); }  // Waits for user ack
	void clearScreen() const { system("cls"); }		// Wipes terminal

private:
	
	class MenuCommands
	{
	public:
		enum class CommandsEnum : uint32_t
		{
			CREATE_ACCOUNT			= 110,
			FETCH_USER_LIST			= 120,
			FETCH_PUBLIC_KEY		= 130,
			CHECK_INBOX				= 140,
			COMPOSE_MESSAGE			= 150,
			REQUEST_ENCRYPTION_KEY  = 151,
			SHARE_ENCRYPTION_KEY    = 152,
			UPLOAD_FILE				= 153,
			QUIT					= 0
		};

	private:
		bool authenticationRequired;    ///< Whether login is needed
		CommandsEnum commandType;       ///< Command identifier
		std::string confirmationText;   ///< Success message
		std::string label;              ///< User-facing command name

	public:
		// Default constructor
		MenuCommands() : commandType(CommandsEnum::QUIT), authenticationRequired(false) {}

		// Full constructor with all metadata
		MenuCommands(const CommandsEnum val, const bool reg, std::string desc, std::string success) : commandType(val),
			authenticationRequired(reg), label(std::move(desc)), confirmationText(std::move(success)) {}

		// Format command for display in terminal
		friend std::ostream& operator<<(std::ostream& os, const MenuCommands& opt) {
			os << std::setw(2) << static_cast<uint32_t>(opt.commandType) << ") " << opt.label;
			return os;
		}

		// Getters
		CommandsEnum getType()					const { return commandType; }
		bool requiresAuthentication()			const { return authenticationRequired; }
		std::string getConfirmationMessage()	const { return confirmationText; }
	};

private:
	// Client instance and authentication status
	bool authenticated;             ///< User authentication status
	MessageEngine engineInstance;   ///< Communication subsystem

	// Exits the application with an error notification
	void terminateWithError(const std::string& errorMessage) const;

	// Captures text entered by the user
	std::string captureInput(const std::string& prompt = "") const;

	// Interprets user input and converts it to a valid command
	bool validateCommandSelection(MenuCommands& selectedCommand) const;

	// Executes the selected command and returns operation result
	bool executeSelectedCommand(const MenuCommands& command);

	// Display helpers
	void displayMessages(const std::vector<MessageEngine::MessageData>& messages) const;
	void displayUserList() const;

	// Available user commands in the menu
	const std::vector<MenuCommands> availableCommands {
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

