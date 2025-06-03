/**
 * @author	Natanel Fishman
 * @file	ConsoleInterface.cpp
 * @brief	Interactive command-line interface for MessageU client
 */
#include "ConsoleInterface.h"
#include <iostream>
#include <algorithm>
#include <boost/algorithm/string/trim.hpp>

// Displays an error message and terminates the application
void ConsoleInterface::terminateWithError(const std::string& errorMessage) const
{
	std::cerr << "Critical Error: " << errorMessage << std::endl;
	std::cerr << "Application will now exit." << std::endl;
	waitForInput();
	exit(EXIT_FAILURE);
}

// Prepare the client interface and establishes connection parameters
void ConsoleInterface::prepare()
{
	if (!engineInstance.loadServerConfiguration())
	{
		terminateWithError(engineInstance.getErrorMessage());
	}
	authenticated = engineInstance.loadUserCredentials();

}

// Renders the main application menu with appropriate user context
void ConsoleInterface::showMenu() const
{
	clearScreen();

	// Display personalized greeting if authenticated
	if (authenticated && !engineInstance.getSelfUsername().empty()) {
		std::cout << "Welcome back " << engineInstance.getSelfUsername() << "! ";
	}

	std::cout << "MessageU client at your service." << std::endl << std::endl;

	// Display available commands
	for (const auto& command : availableCommands) {
		std::cout << command << std::endl;
	}
}


/**
 * Captures user input with validation
 * Ensures non-empty input and handles input stream errors
 */
std::string ConsoleInterface::captureInput(const std::string& prompt) const
{
	std::string input;

	std::cout << prompt << std::endl;
	do
	{
		// Capture user input
		std::getline(std::cin, input);
		boost::algorithm::trim(input);

		// Handle input stream errors
		if (std::cin.eof()) {
			std::cin.clear(); // Reset the stream state
		}

		// Ensure input is not empty
		if (input.empty())
		{
			std::cout << "Input cannot be empty. Please try again:" << std::endl;
		}

	} while (input.empty());

	return input;
}


/**
 * Read & Validate user's input according to main menu options.
 * If valid option, assign menuOption.
 */
bool ConsoleInterface::validateCommandSelection(MenuCommands& selectedCommand) const
{
	const std::string input = captureInput();

	// Find matching command based on numeric input
	const auto commandIterator = std::find_if(availableCommands.begin(), availableCommands.end(),
		[&input](auto& command) { return (input == std::to_string(static_cast<uint32_t>(command.getType()))); });
	
	// Validate command selection
	if (commandIterator == availableCommands.end())
	{
		return false;
	}

	selectedCommand = *commandIterator;
	return true;
}

// Processes and executes the selected command
void ConsoleInterface::processCommand()
{
	MenuCommands selectedCommand;
	bool validSelection = validateCommandSelection(selectedCommand);

	// Handle invalid selection
	while (!validSelection)
	{
		std::cout << "Invalid selection. Please enter a valid command number." << std::endl;
		validSelection = validateCommandSelection(selectedCommand);
	}

	clearScreen();
	std::cout << std::endl;

	// Authentication check
	if (!authenticated && selectedCommand.requiresAuthentication())
	{
		std::cout << "Authentication required. Please register first." << std::endl;
		return;
	}

    // Execute selected command
    bool operationSuccess = executeSelectedCommand(selectedCommand);

    // Display result message
    if (operationSuccess)
    {
        std::cout << selectedCommand.getConfirmationMessage() << std::endl;
    }
    else
    {
        std::cout << engineInstance.getErrorMessage() << std::endl;
    }
}

// Executes the selected command and returns the operation result
bool ConsoleInterface::executeSelectedCommand(const MenuCommands& command)
{
    bool operationSuccess = false;

    switch (command.getType())
    {
    case MenuCommands::CommandsEnum::QUIT:
        std::cout << "Shutting down MessageU client. Goodbye!" << std::endl;
        waitForInput();
        exit(EXIT_SUCCESS);
        break;

    case MenuCommands::CommandsEnum::CREATE_ACCOUNT:
        if (authenticated)
        {
            std::cout << "Account already exists for " << engineInstance.getSelfUsername() << std::endl;
            return false;
        }

        {
            const std::string username = captureInput("Enter desired username:");
            operationSuccess = engineInstance.registerClient(username);
            authenticated = operationSuccess;
        }
        break;

    case MenuCommands::CommandsEnum::FETCH_USER_LIST:
        operationSuccess = engineInstance.requestClientsList();
        if (operationSuccess)
        {
            displayUserList();
        }
        break;

    case MenuCommands::CommandsEnum::FETCH_PUBLIC_KEY:
    {
        const std::string username = captureInput("Enter username to fetch public key:");
        operationSuccess = engineInstance.requestClientPublicKey(username);
    }
    break;

    case MenuCommands::CommandsEnum::CHECK_INBOX:
    {
        std::vector<MessageEngine::MessageData> messages;
        operationSuccess = engineInstance.retrievePendingMessages(messages);
        if (operationSuccess)
        {
            displayMessages(messages);
        }
    }
    break;

    case MenuCommands::CommandsEnum::COMPOSE_MESSAGE:
    {
        const std::string recipient = captureInput("Enter recipient username:");
        const std::string messageContent = captureInput("Enter message content:");
        operationSuccess = engineInstance.sendMessage(recipient, MSG_TEXT, messageContent);
    }
    break;

    case MenuCommands::CommandsEnum::REQUEST_ENCRYPTION_KEY:
    {
        const std::string username = captureInput("Enter username to request encryption key from:");
        operationSuccess = engineInstance.sendMessage(username, MSG_SYMMETRIC_KEY_REQUEST);
    }
    break;

    case MenuCommands::CommandsEnum::SHARE_ENCRYPTION_KEY:
    {
        const std::string username = captureInput("Enter username to share encryption key with:");
        operationSuccess = engineInstance.sendMessage(username, MSG_SYMMETRIC_KEY_SEND);
    }
    break;

    case MenuCommands::CommandsEnum::UPLOAD_FILE:
    {
        const std::string recipient = captureInput("Enter recipient username:");
        const std::string filePath = captureInput("Enter file path:");
        operationSuccess = engineInstance.sendMessage(recipient, MSG_FILE, filePath);
    }
    break;
    }

    return operationSuccess;
}

// Displays the list of registered users
void ConsoleInterface::displayUserList() const
{
    std::vector<std::string> usernames = engineInstance.getUsernames();

    if (usernames.empty())
    {
        std::cout << "No registered users found." << std::endl;
        return;
    }

    std::cout << "Registered Users:" << std::endl;
    std::cout << "----------------" << std::endl;

    for (const auto& username : usernames)
    {
        std::cout << "• " << username << std::endl;
    }
}

// Displays received messages
void ConsoleInterface::displayMessages(const std::vector<MessageEngine::MessageData>& messages) const
{
    if (messages.empty())
    {
        std::cout << "No new messages." << std::endl;
        return;
    }

    std::cout << "Received Messages:" << std::endl;
    std::cout << "-----------------" << std::endl;

    for (const auto& message : messages)
    {
        std::cout << "From: " << message.username << std::endl;
        std::cout << "Content:" << std::endl;
        std::cout << message.content << std::endl;
        std::cout << "-----------------" << std::endl;
    }

    // Display any errors that occurred during message processing
    const std::string errors = engineInstance.getErrorMessage();
    if (!errors.empty())
    {
        std::cout << std::endl << "Message Processing Errors:" << std::endl;
        std::cout << errors << std::endl;
    }
}