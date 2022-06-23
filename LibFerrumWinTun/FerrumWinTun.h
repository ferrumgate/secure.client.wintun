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
	int ferrumStartWinTun(void);
	// stops wintun adapter
	int ferrumStopWinTun(void);
	// create a child process
	int ferrumCreateChildProcess(TCHAR szCmdline[], PROCESS_INFORMATION* pi);
	// wait for created child process to finish
	int ferrumWaitChildProcess(PROCESS_INFORMATION* pi);

#ifdef __cplusplus
}
#endif
