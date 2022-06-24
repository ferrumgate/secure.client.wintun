#include "pch.h"
#include "CppUnitTest.h"
#include "FerrumWinTun.h"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTestLibFerrum
{
	TEST_CLASS(UnitTestFerrumWinTun)
	{
	public:
		
		TEST_METHOD(_FerrumStartStopWinTun)
		{
			int result = FerrumStartWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);
			Assert::IsNotNull(ferrum.adapter);
			Assert::IsTrue(ferrum.loadedLib > 0);
			Assert::IsTrue(ferrum.work == 0);
			result = FerrumStopWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);
		}

		TEST_METHOD(_FerrumCreateChildProcess)
		{
			PROCESS_INFORMATION pi;

			TCHAR cmd[] =  TEXT("powershell.exe ls");
			int result = FerrumCreateChildProcess(cmd,&pi);
			Assert::IsTrue(result == ERROR_SUCCESS);
			Assert::IsNotNull(pi.hProcess);
			Assert::IsTrue(pi.dwProcessId>0);
			Assert::IsNotNull(ferrum.childProcess.stderrRD);
			Assert::IsNotNull(ferrum.childProcess.stderrWR);
			Assert::IsNotNull(ferrum.childProcess.stdinRD);
			Assert::IsNotNull(ferrum.childProcess.stdinWR);
			Assert::IsNotNull(ferrum.childProcess.stdoutRD);
			Assert::IsNotNull(ferrum.childProcess.stdoutWR);
			Assert::IsNotNull(ferrum.childProcess.stdoutThread);
			Assert::IsNotNull(ferrum.childProcess.stderrThread);			

			result=FerrumWaitChildProcess(&pi);
			
		}
		static int TestCreatePipe() {
			HANDLE pipe=NULL;
			DWORD   cbToWrite, cbWritten;
			int result = FerrumCreatePipe(TEXT("\\\\.\\pipe\\mynamedpipe"),&pipe);
			Assert::IsTrue(result == ERROR_SUCCESS);
			Assert::IsNotNull(pipe);
			LPTSTR lpvMessage = TEXT("Default message from client.");
			cbToWrite = (lstrlen(lpvMessage) + 1) * sizeof(TCHAR);
			int fSuccess = WriteFile(
				pipe,                  // pipe handle 
				lpvMessage,             // message 
				cbToWrite,              // message length 
				&cbWritten,             // bytes written 
				NULL);                  // not overlapped 

			Assert::IsTrue(fSuccess>0);
			CloseHandle(pipe);
			return ERROR_SUCCESS;
		};

		TEST_METHOD(_FerrumCreatePipe)
		{
			LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");
		 HANDLE thread=	CreateThread(NULL,0,
				(LPTHREAD_START_ROUTINE) TestCreatePipe,
				(LPVOID)NULL, 0, NULL);
		 Assert::IsNotNull(thread);
		 WaitForSingleObject(thread, 100);
		 HANDLE clientpipe= CreateFile(
			lpszPipename,   // pipe name 
			 GENERIC_READ |  // read and write access 
			 GENERIC_WRITE,
			 0,              // no sharing 
			 NULL,           // default security attributes
			 OPEN_EXISTING,  // opens existing pipe 
			 0,              // default attributes 
			 NULL);          // no template file 
		 Assert::IsTrue(clientpipe != INVALID_HANDLE_VALUE);
		 DWORD lastError = GetLastError();
		 Assert::IsTrue(lastError != ERROR_PIPE_BUSY);

		 DWORD  cbRead;
		 TCHAR  chBuf[4096] = { 0, };
		 int fSuccess = ReadFile(
			 clientpipe,    // pipe handle 
			 chBuf,    // buffer to receive reply 
			 4096 * sizeof(TCHAR),  // size of buffer 
			 &cbRead,  // number of bytes read 
			 NULL);
		 Assert::IsTrue(fSuccess>0);
		 Assert::AreEqual(chBuf, TEXT("Default message from client."));
		 WaitForSingleObject(thread, INFINITE);
		 CloseHandle(clientpipe);

		}

		TEST_METHOD(_FerrumRxTxWinTun)
		{
			int result = FerrumStartWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);

			result=FerrumRxTxWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);
			
			PROCESS_INFORMATION pi;
			ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
			result=FerrumCreateChildProcess(L"powershell.exe sleep 10", &pi);
			Assert::IsTrue(result == ERROR_SUCCESS);

			LPTSTR lpszPipeRead = TEXT("\\\\.\\pipe\\ferrum_read");
			LPTSTR lpszPipeWrite = TEXT("\\\\.\\pipe\\ferrum_write");

			// connect to read and write pipes
			HANDLE pipeRead = CreateFile(
				lpszPipeRead,
				GENERIC_READ |
				GENERIC_WRITE,
				0,
				NULL,
				OPEN_EXISTING,
				0,
				NULL);
			HANDLE pipeWrite = CreateFile(
				lpszPipeWrite,
				GENERIC_READ |
				GENERIC_WRITE,
				0,
				NULL,
				OPEN_EXISTING,
				0,
				NULL);

			Assert::IsNotNull(pipeWrite);
			Assert::IsNotNull(pipeRead);
			// write some data to writable pipe
			DWORD written;
			BOOL fsuccess = WriteFile(pipeWrite, "TEST", 5, &written, NULL);
			Assert::IsTrue(fsuccess);
			FerrumWaitChildProcess(&pi);

			FerrumStopWinTun();

		}
	};
}
