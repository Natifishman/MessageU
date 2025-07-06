/**
 * @file        main.cpp
 * @author      Natanel Maor Fishman
 * @brief       MessageU Client - Main application entry point
 * @details     Secure messaging client application providing encrypted communication
 *              capabilities with comprehensive user interface and network connectivity
 * @version     2.0
 * @date        2025
 * @note        This is the main entry point for the MessageU client application
 */

#include "ConsoleInterface.h"

 /**
  * @brief       Main application entry point
  * @param[in]   argumentCount     Number of command line arguments
  * @param[in]   argumentVector    Array of command line argument strings
  * @return      EXIT_SUCCESS on normal termination, EXIT_FAILURE on error
  * @details     Initializes the client application and enters the main event loop.
  *              Provides secure messaging capabilities with encrypted communication.
  *              The application runs continuously until explicitly terminated.
  */
int main(int argumentCount, char* argumentVector[])
{
	// Initialize the console interface for user interaction
	ConsoleInterface userInterface;

	// Prepare the interface and establish initial connections
	userInterface.prepare();

	// Main application event loop
	while (true) {
		// Display the main menu to the user
		userInterface.showMenu();

		// Process user commands and handle application logic
		userInterface.processCommand();

		// Wait for user input before continuing
		userInterface.waitForInput();
	}

	// This point is never reached in normal operation
	// The application runs continuously until terminated
	return EXIT_SUCCESS;
}