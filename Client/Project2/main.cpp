/**
 * @author      Natanel Maor Fishman
 * @file        main.cpp
 * @brief       Client   - entry point.
 * @note        MessageU - Client Side main program.
 * @version     2.0
 */
#include "ConsoleInterface.h"
int main(int argc, char argv[])
{
	ConsoleInterface menu;
	menu.prepare(); 

	while (true) //infinte loop
	{
		menu.showMenu();
		menu.processCommand();
		menu.waitForInput();
	}

	return EXIT_SUCCESS;
}