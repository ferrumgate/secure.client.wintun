#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <wintun.h>

	typedef struct {
		// loaded wintun.dll
		int loadedLib;
		// is initted wintun adapter
		int initted;
		// adapter starter successfully
		int work;
		// wintun handle
		HMODULE wintun;
		// wintun adapter
		WINTUN_ADAPTER_HANDLE adapter;
		HANDLE quitEvent;
		//executed child process structure
		struct {
			//process info
			PROCESS_INFORMATION info;
			// pipe stdin read
			HANDLE stdinRD;
			// pipe stdin write
			HANDLE stdinWR;
			// pipe stdout read
			HANDLE stdoutRD;
			// pipe stdout write
			HANDLE stdoutWR;
			// pipe stderr read
			HANDLE stderrRD;
			// pipe stderr write
			HANDLE stderrWR;
			// stdout watch thread
			HANDLE stdoutThread;
			// stderr watch thread
			HANDLE stderrThread;
		}childProcess;

		
	}ferrum_t;

	// global ferrum object for states
	ferrum_t ferrum;
#ifdef __cplusplus
}
#endif