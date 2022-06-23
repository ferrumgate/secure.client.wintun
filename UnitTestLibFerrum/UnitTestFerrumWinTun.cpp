#include "pch.h"
#include "CppUnitTest.h"
#include "FerrumWinTun.h"
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTestLibFerrum
{
	TEST_CLASS(UnitTestFerrumWinTun)
	{
	public:
		
		TEST_METHOD(_ferrumStartStopWinTun)
		{
			int result = ferrumStartWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);
			Assert::IsNotNull(ferrum.adapter);
			Assert::IsTrue(ferrum.loadedLib > 0);
			Assert::IsTrue(ferrum.work == 0);
			result = ferrumStopWinTun();
			Assert::IsTrue(result == ERROR_SUCCESS);
		}

		TEST_METHOD(_createChildProcess)
		{
			PROCESS_INFORMATION pi;

			TCHAR cmd[] =  TEXT("powershell.exe ls");
			int result = ferrumCreateChildProcess(cmd,&pi);
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

			result=ferrumWaitChildProcess(&pi);
			
		}
	};
}
