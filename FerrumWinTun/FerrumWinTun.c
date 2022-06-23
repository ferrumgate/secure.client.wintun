// FerrumWinTun.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "FerrumWinTun.h"

static void onExit(void) {
	fprintf(stderr, "onexit\n");
	ferrumStopWinTun();
}

int main(int argc, char* argv[])
{
	atexit(onExit);
	//start tunnel
	int result=ferrumStartWinTun();
	if (result != ERROR_SUCCESS) {

		exit(result);
	}
	//on exit stop tunnel
	
	fprintf(stdout, "%d %s %s\n", argc, argv[0],argv[1]);
	//create child secure connection over ssh
	TCHAR cmd[1024] = { 0, };
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[1], (size_t)strlen(argv[1]),cmd, 1024);
	result = ferrumCreateChildProcess(cmd, &ferrum.childProcess.info);
	if (result != ERROR_SUCCESS) {
		exit(result);
	}
	ferrumWaitChildProcess(&ferrum.childProcess);
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
