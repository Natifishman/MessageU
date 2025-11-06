/**
 * @file        main.cpp
 * @author      Natanel Maor Fishman
 * @brief       MessageU Client - Main application entry point
 * @details     Secure messaging client application providing encrypted communication
 *              capabilities with comprehensive user interface and network connectivity.
 *              This is the main entry point that initializes the client application
 *              and manages the main event loop for user interaction.
 * @version     2.0
 * @date        2025
 * @note        This is the main entry point for the MessageU client application
 */

// ================================
// Standard Library Includes
// ================================

#include <cstdlib>
#include <iostream>

// ================================
// Application Includes
// ================================

#include "ConsoleInterface.h"

// ================================
// Function Definitions
// ================================

/**
 * @brief       Main application entry point
 * @param[in]   argumentCount     Number of command line arguments
 * @param[in]   argumentVector    Array of command line argument strings
 * @return      EXIT_SUCCESS on normal termination, EXIT_FAILURE on error
 * @details     Initializes the client application and enters the main event loop.
 *              Provides secure messaging capabilities with encrypted communication.
 *              The application runs continuously until explicitly terminated.
 *              Handles graceful shutdown and error conditions.
 *              
 *              Program Flow:
 *              1. Initialize console interface
 *              2. Prepare interface and establish connections
 *              3. Enter main event loop (menu display and command processing)
 *              4. Handle graceful shutdown
 */
int main(int argumentCount, char* argumentVector[])
{
	// ================================
	// Application Initialization
	// ================================
	
	// Initialize the console interface for user interaction
	ConsoleInterface userInterface;

	// Prepare the interface and establish initial connections
	userInterface.prepare();

	// ================================
	// Main Application Event Loop
	// ================================
	
	while (true) {
		// Display the main menu to the user
		userInterface.showMenu();

		// Process user commands and handle application logic
		userInterface.processCommand();

		// Wait for user input before continuing
		userInterface.waitForInput();
	}

	// ================================
	// Application Termination
	// ================================
	
	// This point is never reached in normal operation
	// The application runs continuously until terminated
	return EXIT_SUCCESS;
}