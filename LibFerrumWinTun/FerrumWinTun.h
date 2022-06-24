#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <ip2string.h>
#include <winternl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <wintun.h>
#include "Ferrum.h"


	// starts wintun adapter
	int FerrumStartWinTun(void);
	// stops wintun adapter
	int FerrumStopWinTun(void);
	// start send/receive
	int FerrumRxTxWinTun(void);
	// create a named pipe between for using between child and parent
	int FerrumCreatePipe(const TCHAR name[], __inout HANDLE* pipe);
	// create a child process
	int FerrumCreateChildProcess(TCHAR szCmdline[], PROCESS_INFORMATION* pi);
	// wait for created child process to finish
	int FerrumWaitChildProcess(PROCESS_INFORMATION* pi);


#ifdef __cplusplus
}
#endif
