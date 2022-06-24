/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "ferrumWinTun.h"


static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;


#define BUFSIZE 4096

DWORD
LogError(_In_z_ const WCHAR* Prefix, _In_ DWORD Error);

static DWORD64 Now(VOID)
{
    LARGE_INTEGER Timestamp;
    NtQuerySystemTime(&Timestamp);
    return Timestamp.QuadPart;
}

static DWORD
LogLastError(_In_z_ const WCHAR* Prefix)
{
    DWORD LastError = GetLastError();
    LogError(Prefix, LastError);
    SetLastError(LastError);
    return LastError;
}

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR* LogLine)
{
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime((FILETIME*)&Timestamp, &SystemTime);
    WCHAR LevelMarker;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        LevelMarker = L'+';
        break;
    case WINTUN_LOG_WARN:
        LevelMarker = L'-';
        break;
    case WINTUN_LOG_ERR:
        LevelMarker = L'!';
        break;
    default:
        return;
    }
    fwprintf(
        stderr,
        L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond,
        SystemTime.wMilliseconds,
        LevelMarker,
        LogLine);
}


static DWORD
LogError(_In_z_ const WCHAR* Prefix, _In_ DWORD Error)
{
    WCHAR* SystemMessage = NULL, * FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (void*)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
        FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
        0,
        0,
        (void*)&FormattedMessage,
        0,
        (va_list*)(DWORD_PTR[]) { (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
    if (FormattedMessage)
        ConsoleLogger(WINTUN_LOG_ERR, Now(), FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}


static HMODULE
InitializeWintun(void)
{
    //WCHAR cwd[128];
    //GetCurrentDirectoryW(sizeof(cwd)/2, cwd);
    //WCHAR cwdf[128];
    //_snwprintf_s(cwdf, sizeof(cwdf)/2,128, L"cwd is %s", cwd);
    //ConsoleLogger(WINTUN_LOG_INFO, Now(), cwdf);
    
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!Wintun) {
        return NULL;
    }
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}







static void
Log(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR* Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, Now(), LogLine);
}




static BOOL WINAPI
CtrlHandler(_In_ DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        Log(WINTUN_LOG_INFO, L"cleaning up and shutting down...");
        ferrum.work = FALSE;
        SetEvent(ferrum.quitEvent);
        return TRUE;
    }
    return FALSE;
}

static void
PrintPacket(_In_ const BYTE* Packet, _In_ DWORD PacketSize)
{
    if (PacketSize < 20)
    {
        Log(WINTUN_LOG_INFO, L"received packet without room for an IP header");
        return;
    }
    BYTE IpVersion = Packet[0] >> 4, Proto;
    WCHAR Src[46], Dst[46];
    if (IpVersion == 4)
    {
        RtlIpv4AddressToStringW((struct in_addr*)&Packet[12], Src);
        RtlIpv4AddressToStringW((struct in_addr*)&Packet[16], Dst);
        Proto = Packet[9];
        Packet += 20, PacketSize -= 20;
    }
    else if (IpVersion == 6 && PacketSize < 40)
    {
        Log(WINTUN_LOG_INFO, L"received packet without room for an IP header");
        return;
    }
    else if (IpVersion == 6)
    {
        RtlIpv6AddressToStringW((struct in6_addr*)&Packet[8], Src);
        RtlIpv6AddressToStringW((struct in6_addr*)&Packet[24], Dst);
        Proto = Packet[6];
        Packet += 40, PacketSize -= 40;
    }
    else
    {
        Log(WINTUN_LOG_INFO, L"received packet that was not IP");
        return;
    }
    if (Proto == 1 && PacketSize >= 8 && Packet[0] == 0)
        Log(WINTUN_LOG_INFO, L"received IPv%d ICMP echo reply from %s to %s", IpVersion, Src, Dst);
    else
        Log(WINTUN_LOG_INFO, L"received IPv%d proto 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
}

static USHORT
IPChecksum(_In_reads_bytes_(Len) BYTE* Buffer, _In_ DWORD Len)
{
    ULONG Sum = 0;
    for (; Len > 1; Len -= 2, Buffer += 2)
        Sum += *(USHORT*)Buffer;
    if (Len)
        Sum += *Buffer;
    Sum = (Sum >> 16) + (Sum & 0xffff);
    Sum += (Sum >> 16);
    return (USHORT)(~Sum);
}

static void
MakeICMP(_Out_writes_bytes_all_(28) BYTE Packet[28])
{
    memset(Packet, 0, 28);
    Packet[0] = 0x45;
    *(USHORT*)&Packet[2] = htons(28);
    Packet[8] = 255;
    Packet[9] = 1;
    *(ULONG*)&Packet[12] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (8 << 0)); /* 10.6.7.8 */
    *(ULONG*)&Packet[16] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
    *(USHORT*)&Packet[10] = IPChecksum(Packet, 20);
    Packet[20] = 8;
    *(USHORT*)&Packet[22] = IPChecksum(&Packet[20], 8);
    Log(WINTUN_LOG_INFO, L"sending IPv4 ICMP echo request to 10.6.7.8 from 10.6.7.7");
}



int __cdecl 
FerrumStartWinTun()
{
    //clear all states
    ZeroMemory(&ferrum, sizeof(ferrum));
    HMODULE Wintun = InitializeWintun();
    if (!Wintun)
        return LogError(L"failed to initialize Wintun", GetLastError());
    ferrum.loadedLib = 1;
    WintunSetLogger(ConsoleLogger);
    Log(WINTUN_LOG_INFO, L"wintun library loaded");

    DWORD LastError = ERROR_SUCCESS;
    
    ferrum.quitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ferrum.quitEvent)
    {
        LastError = LogError(L"failed to create event", GetLastError());
        goto cleanupWintun;
    }
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        LastError = LogError(L"failed to set console handler", GetLastError());
        goto cleanupQuit;
    }
    
    GUID guid = { 0x43dad8f2, 0x3304, 0x4033, { 0x8a, 0x6a, 0xb9, 0x47, 0x0c, 0x10, 0xc5, 0x75 } };
    

    WINTUN_ADAPTER_HANDLE Adapter = WintunCreateAdapter(L"FerrumGate", L"Secure", &guid);
    if (!Adapter)
    {
        LastError = GetLastError();
        LogError(L"failed to create adapter", LastError);
        goto cleanupQuit;
        /*Adapter = WintunOpenAdapter(L"FerrumGate");
        if (!Adapter)
        {
            LastError = GetLastError();
            LogError(L"Failed to open adapter", LastError);
            goto cleanupQuit;
        }*/
    }
   

    DWORD Version = WintunGetRunningDriverVersion();
    Log(WINTUN_LOG_INFO, L"wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);
   /* LastError = ERROR_SUCCESS;
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);*/
    //AddressRow.Address.Ipv4.sin_family = AF_INET;
    //AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); // 10.6.7.7 
    //AddressRow.OnLinkPrefixLength = 24; // This is a /24 network 
    //AddressRow.DadState = IpDadStatePreferred;
    //LastError = CreateUnicastIpAddressEntry(&AddressRow);
  /*  if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }

    WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter, 0x400000);
    if (!Session)
    {
        LastError = LogLastError(L"Failed to create adapter");
        goto cleanupAdapter;
    }

    Log(WINTUN_LOG_INFO, L"Launching threads and mangling packets...");

    HANDLE Workers[] = { CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)Session, 0, NULL),
                         CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendPackets, (LPVOID)Session, 0, NULL) };
    if (!Workers[0] || !Workers[1])
    {
        LastError = LogError(L"Failed to create threads", GetLastError());
        goto cleanupWorkers;
    }
    WaitForMultipleObjectsEx(_countof(Workers), Workers, TRUE, INFINITE, TRUE);
    LastError = ERROR_SUCCESS;

cleanupWorkers:
    HaveQuit = TRUE;
    SetEvent(QuitEvent);
    for (size_t i = 0; i < _countof(Workers); ++i)
    {
        if (Workers[i])
        {
            WaitForSingleObject(Workers[i], INFINITE);
            CloseHandle(Workers[i]);
        }
    }
    WintunEndSession(Session);

    getchar();*/
    ferrum.wintun = Wintun;
    ferrum.adapter = Adapter;
    ferrum.initted = 1;
    return LastError;
cleanupAdapter:
    WintunCloseAdapter(Adapter);
cleanupQuit:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    CloseHandle(ferrum.quitEvent);
cleanupWintun:
    FreeLibrary(Wintun);
    return LastError;
}

int __cdecl 
FerrumStopWinTun() {
    if (ferrum.initted) {
        SetEvent(ferrum.quitEvent);
        if (ferrum.session)
            WintunEndSession(ferrum.session);
        WintunCloseAdapter(ferrum.adapter);
        SetConsoleCtrlHandler(CtrlHandler, FALSE);
        CloseHandle(ferrum.quitEvent);
       
    }
    if(ferrum.loadedLib)
    FreeLibrary(ferrum.wintun);
    ZeroMemory(&ferrum, sizeof(ferrum));

    return ERROR_SUCCESS;
    
}



// read child process stdout and write to parent stdout
static DWORD WINAPI
ReadFromChildStdOut()
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    
    while (ferrum.work)
    {
        
        bSuccess = ReadFile(ferrum.childProcess.stdoutRD, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;
        
        bSuccess = WriteFile(hParentStdOut, chBuf,
            dwRead, &dwWritten, NULL);
        if (!bSuccess) break;
    }
    return ERROR_SUCCESS;
}

// read child process stderr and write to parent stderr
static DWORD WINAPI
ReadFromChildStdErr()
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hParentStdErr = GetStdHandle(STD_ERROR_HANDLE);

    while (ferrum.work)
    {

        bSuccess = ReadFile(ferrum.childProcess.stderrRD, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        bSuccess = WriteFile(hParentStdErr, chBuf,
            dwRead, &dwWritten, NULL);
        if (!bSuccess) break;
    }
    return ERROR_SUCCESS;
}

int FerrumCreateChildProcess(TCHAR szCmdline[], PROCESS_INFORMATION* pi)
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{   

    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited. 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT. 
    if (!CreatePipe(&ferrum.childProcess.stdoutRD, &ferrum.childProcess.stdoutWR, &saAttr, 0)) {
        LogLastError(TEXT("stdoutRd CreatePipe failed:"));
        return ERROR_PROCESS_ABORTED;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(ferrum.childProcess.stdoutRD, HANDLE_FLAG_INHERIT, 0)){
        LogLastError(TEXT("StdoutRD SetHandleInformation failed:"));
        return ERROR_PROCESS_ABORTED;
    }


    // Create a pipe for the child process's STDERR. 
    if (!CreatePipe(&ferrum.childProcess.stderrRD, &ferrum.childProcess.stderrWR, &saAttr, 0)) {
        LogLastError(TEXT("stdoutRd CreatePipe failed:"));
        return ERROR_PROCESS_ABORTED;
    }

    // Ensure the read handle to the pipe for STDERR is not inherited.
    if (!SetHandleInformation(ferrum.childProcess.stderrRD, HANDLE_FLAG_INHERIT, 0)){
        LogLastError(TEXT("stderrRD SetHandleInformation failed:"));
        return ERROR_PROCESS_ABORTED;
    }



    // Create a pipe for the child process's STDIN. 
    if (!CreatePipe(&ferrum.childProcess.stdinRD, &ferrum.childProcess.stdinWR, &saAttr, 0)){
        LogLastError(TEXT("stdinRD CreatePipe failed:"));
        return ERROR_PROCESS_ABORTED;
    }

    // Ensure the write handle to the pipe for STDIN is not inherited. 
    if (!SetHandleInformation(ferrum.childProcess.stdinWR, HANDLE_FLAG_INHERIT, 0)){
        LogLastError(TEXT("stdinWR SetHandleInformation failed:"));
        return ERROR_PROCESS_ABORTED;
    }




    
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    // Set up members of the PROCESS_INFORMATION structure. 

    ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = ferrum.childProcess.stderrWR;
    siStartInfo.hStdOutput = ferrum.childProcess.stdoutWR;
    siStartInfo.hStdInput = ferrum.childProcess.stdinRD;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 
    LPTSTR cmd = _tcsdup(szCmdline);
    bSuccess = CreateProcess(NULL,
        cmd,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        pi);  // receives PROCESS_INFORMATION 
    free(cmd);
    // If an error occurs, exit the application. 
    if (!bSuccess)
    {
        LogLastError(L"process create failed: ");
        return ERROR_PROCESS_ABORTED;
    }
    ferrum.work = TRUE;
    ferrum.childProcess.stdoutThread= CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReadFromChildStdOut, (LPVOID)NULL, 0, NULL);
    ferrum.childProcess.stderrThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReadFromChildStdErr, (LPVOID)NULL, 0, NULL);
    return ERROR_SUCCESS;
   
}

int FerrumWaitChildProcess(PROCESS_INFORMATION* pi) {
    WaitForSingleObject(pi->hProcess, INFINITE);
    ferrum.work = FALSE;
    SetEvent(ferrum.quitEvent);
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
    CloseHandle(ferrum.childProcess.stderrWR);
    CloseHandle(ferrum.childProcess.stdoutWR);
    CloseHandle(ferrum.childProcess.stdinRD);
    CloseHandle(ferrum.childProcess.stderrThread);
    CloseHandle(ferrum.childProcess.stdoutThread);
  //  CloseHandle(ferrum.childPipe.read);
  //  CloseHandle(ferrum.childPipe.write);
    

    return ERROR_SUCCESS;
}


int
FerrumCreatePipe(const TCHAR name[],__inout HANDLE *pipe) {
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
    LPCTSTR lpszPipename = name;
    // The main loop creates an instance of the named pipe and 
// then waits for a client to connect to it. When the client 
// connects, a thread is created to handle communications 
// with that client, and this loop is free to wait for the
// next client connect request. It is an infinite loop.


        
        hPipe = CreateNamedPipe(
            lpszPipename,             // pipe name 
            PIPE_ACCESS_DUPLEX,       // read/write access 
            PIPE_TYPE_BYTE |       // byte type pipe 
            PIPE_READMODE_BYTE |   // byte-read mode 
            PIPE_WAIT,                // blocking mode 
            PIPE_UNLIMITED_INSTANCES, // max. instances  
            BUFSIZE,                  // output buffer size 
            BUFSIZE,                  // input buffer size 
            0,                        // client time-out 
            NULL);                    // default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            return LogLastError(TEXT("create named pipe failed"));
            
        }

        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (fConnected)
        {
            *pipe = hPipe;
            return ERROR_SUCCESS;
        }
        
            // The client could not connect, so close the pipe. 
            CloseHandle(hPipe);
        return ERROR_PIPE_CONNECTED;
    
}

static DWORD WINAPI
ReceivePackets(_Inout_ DWORD_PTR SessionPtr)
{
    WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)SessionPtr;
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session), ferrum.quitEvent };
    int result=FerrumCreatePipe(TEXT("\\\\.\\pipe\\ferrum_read"),&ferrum.childPipe.read);
    if (result) {
       return LogLastError(TEXT("read pipe create failed:"));
        
    }

    while (ferrum.work)
    {
        DWORD PacketSize;
        BYTE* Packet = WintunReceivePacket(Session, &PacketSize);
        if (Packet)
        {
            DWORD written;
            PrintPacket(Packet, PacketSize);
            BOOL fSuccess = WriteFile(ferrum.childPipe.read, Packet, PacketSize, &written, NULL);
            WintunReleaseReceivePacket(Session, Packet);
            if (!fSuccess)
            {
                return LogLastError(L"childpipe write error:");
                
            }
        }
        else
        {
            DWORD LastError = GetLastError();
            switch (LastError)
            {
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                return ERROR_SUCCESS;
            default:
                LogError(L"packet read failed", LastError);
                return LastError;
            }
        }
    }
    return ERROR_SUCCESS;
}

static DWORD WINAPI
SendPackets(_Inout_ DWORD_PTR SessionPtr)
{
    WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)SessionPtr;
   
    int result = FerrumCreatePipe(TEXT("\\\\.\\pipe\\ferrum_write"), &ferrum.childPipe.write);
    if (result) {
       return LogLastError(TEXT("read pipe create failed:"));        
    }
    HANDLE WaitHandles[] = { ferrum.childPipe.write, ferrum.quitEvent };
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL fSuccess;
    while (ferrum.work)
    {
        fSuccess=ReadFile(ferrum.childPipe.write, chBuf, BUFSIZE, &dwRead, NULL);
        if (!fSuccess) {
           return LogLastError(L"read pipe error:");
            
        }
        BYTE* Packet = WintunAllocateSendPacket(Session, dwRead);
        if (Packet)
        {
            memcpy(Packet, chBuf, dwRead);
            WintunSendPacket(Session, Packet);
        }
        else if (GetLastError() != ERROR_BUFFER_OVERFLOW)
            return LogLastError(L"Packet write failed");

        //switch (WaitForSingleObject(ferrum.quitEvent, 1000 /* 1 second */))
        //{
        //case WAIT_ABANDONED:
        //case WAIT_OBJECT_0:
        //    return ERROR_SUCCESS;
        //}
    }
    return ERROR_SUCCESS;
}

int FerrumRxTxWinTun(void) {
    DWORD  LastError = ERROR_SUCCESS;
   // MIB_UNICASTIPADDRESS_ROW AddressRow;
  /*  InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);*/
    //AddressRow.Address.Ipv4.sin_family = AF_INET;
    //AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); // 10.6.7.7 
    //AddressRow.OnLinkPrefixLength = 24; // This is a /24 network 
    //AddressRow.DadState = IpDadStatePreferred;
    //LastError = CreateUnicastIpAddressEntry(&AddressRow);
   /* if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }*/
    ferrum.work = TRUE;
    WINTUN_SESSION_HANDLE Session = WintunStartSession(ferrum.adapter, 0x400000);
    if (!Session)
    {
        LastError = LogLastError(L"Failed to create tun session");
        return LastError;
    }

    Log(WINTUN_LOG_INFO, L"launching threads and mangling packets...");

    HANDLE Workers[] = { CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)Session, 0, NULL),
                         CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendPackets, (LPVOID)Session, 0, NULL) };
    if (!Workers[0] || !Workers[1])
    {
        LastError = LogError(L"Failed to create threads", GetLastError());
        goto cleanupWorkers;
    }
    ferrum.tunThread.read = Workers[0];
    ferrum.tunThread.write = Workers[1];
    ferrum.session = Session;
    //WaitForMultipleObjectsEx(_countof(Workers), Workers, TRUE, INFINITE, TRUE);
    Sleep(500);
    return ERROR_SUCCESS;

cleanupWorkers:
    ferrum.work = FALSE;
    SetEvent(ferrum.quitEvent);
    for (size_t i = 0; i < _countof(Workers); ++i)
    {
        if (Workers[i])
        {
            WaitForSingleObject(Workers[i], INFINITE);
            CloseHandle(Workers[i]);
        }
    }
    WintunEndSession(Session);
}


