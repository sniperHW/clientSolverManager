
#include  "rpipe.h"
#include  <string>
//#define NAME_PIPE_1  "\\\\.\\Global\\ResolverPipe_1"
//#define NAME_PIPE_2  "\\\\.\\Global\\ResolverPipe_2"

#define NAME_PIPE_PREFIX    "\\\\.\\pipe\\ResolverPipe"
#define NAME_PIPE_READ_PREFIX    "READ"
#define NAME_PIPE_WRITE_PREFIX   "WRITE"

using namespace std;

FuncTaskFinish g_funTaskFinished = NULL;
void TaskFail(const string& sTaskID);

CResolverPipe::CResolverPipe()
{
    m_nIterationNum = 0;
    m_dwStartTick = GetTickCount();
    m_dwFinishedSeconds = 0;
    m_dwProcessIndex = 0;
    m_strTaskID = "";
    m_hPipeRead = INVALID_HANDLE_VALUE;
    m_hPipeWrite = INVALID_HANDLE_VALUE;
    m_bRun = TRUE;
    m_dwProcessState = STATE_PROCESS_STOPPED;
    m_hEventStop =CreateEventA(NULL, TRUE, FALSE, NULL);
    m_bNeedReRuntask = FALSE;
    m_bCanDisconnectPipe = FALSE;
    m_dwRetryCount = 0;
    m_dwReCreateProcessCount = 0;
    m_hSolverProcess = INVALID_HANDLE_VALUE;
}
 CResolverPipe::~CResolverPipe()
{

}

DWORD WINAPI ReadPipeThreadProc(LPVOID lpParamter)
{

    CResolverPipe* lpPipe = (CResolverPipe*)lpParamter;

    lpPipe->ReadPipeProc();
    return 0;
}



DWORD WINAPI ThreadProcMonitorProcess(LPVOID lpParamter)

{

    CResolverPipe* lpPipe = (CResolverPipe*)lpParamter;

    lpPipe->ThreadProcMonitorProcess();
    return 0;
}

int   CResolverPipe::InitPipe( )
{
	int iRet = 0;
	char cName_pipe_Read[256] = { 0 };
	char cName_pipe_Write[256] = { 0 };
	if (1 != m_dwProcessIndex && 2 != m_dwProcessIndex)
	{
		printf(" InitPipe invalid process index: %d \n ", m_dwProcessIndex);
		return -1;
	}
	sprintf_s(cName_pipe_Read, 256, "%s_%s_%d", NAME_PIPE_PREFIX, NAME_PIPE_READ_PREFIX, m_dwProcessIndex);
	sprintf_s(cName_pipe_Write, 256, "%s_%s_%d", NAME_PIPE_PREFIX, NAME_PIPE_WRITE_PREFIX, m_dwProcessIndex);

	m_hPipeRead = CreateNamedPipeA(
		cName_pipe_Read,             // pipe name 
		PIPE_ACCESS_INBOUND,//PIPE_ACCESS_DUPLEX,       // read/write access 
		PIPE_TYPE_MESSAGE |       // message type pipe 
		PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		0,                  // output buffer size 
		4096,                  // input buffer size 
		100000,                        // client time-out 
		NULL);                    // default security attribute 
	if (m_hPipeRead == INVALID_HANDLE_VALUE)
	{
		printf(TEXT("CreateNamedPipe read failed, GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
		iRet = -2;
	}
	m_hPipeWrite = CreateNamedPipeA(
		cName_pipe_Write,             // pipe name 
		PIPE_ACCESS_DUPLEX,       // read/write access //PIPE_ACCESS_OUTBOUND
		PIPE_TYPE_MESSAGE |       // message type pipe 
	   PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		4096,                  // output buffer size 
		4096,                  // input buffer size 
		100000,                        // client time-out 
		NULL);                    // default security attribute 
	if (m_hPipeWrite == INVALID_HANDLE_VALUE)
	{
		printf(TEXT("CreateNamedPipe wrtie failed, GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
		iRet = -2;
	}
   
	if (0 != iRet)
	{
		if (m_hPipeRead != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hPipeRead);
		}
		if (m_hPipeWrite != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hPipeWrite);
		}
		return iRet;
	}
	return 0;
}

DWORD CResolverPipe::Start(int dwProcessIndex)
{
    m_dwProcessIndex = dwProcessIndex;
    int iRet = InitPipe();
    if (0 != iRet)
    {
        printf(" Init Pipe failed:%d --Proecess:%d\n", iRet, dwProcessIndex);
        return 1;
    }
    HANDLE hThread = CreateThread(NULL, 0, ReadPipeThreadProc, this, 0, NULL);
    CloseHandle(hThread);

    hThread = CreateThread(NULL, 0, ::ThreadProcMonitorProcess, this, 0, NULL);
    CloseHandle(hThread);
    return 0;
}

int CResolverPipe::StartResolverProcess()
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEX si = { 0 };
    int      iRet = 0;
    int     nIndex = 0;

    LPPROC_THREAD_ATTRIBUTE_LIST pAttribs = NULL;
    WORD iNuma = (WORD)(m_dwProcessIndex - 1);
    //STARTUPINFOEX sInfoEx;
    //sInfoEx.StartupInfo.cb = sizeof(sInfoEx);
    SIZE_T size = { 0 };
    BOOL  bSuccess = FALSE;
   // auto fCreationFlags = EXTENDED_STARTUPINFO_PRESENT;
    char sCommand[512] = { 0 };

    if (m_strExePath.empty())
    {
        printf(" create Process m_strExePath is empty");
        return -101;
    }

     bSuccess = InitializeProcThreadAttributeList(0, 1, 0, &size);
    if ((SIZE_T)0 == size)
    {
        printf("InitializeProcThreadAttributeList failed:%d\n", GetLastError());
        return -102;
    }
    pAttribs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
    if (NULL == pAttribs)
    {
        printf("mem allloc failed:%d\n", GetLastError());
        return -103;
    }
    bSuccess = InitializeProcThreadAttributeList(pAttribs, 1, 0, &size);
    if (FALSE == bSuccess)
    {
        printf("InitializeProcThreadAttributeList----2 failed:%d\n", GetLastError());
        if (NULL != pAttribs)
        {
            bSuccess = HeapFree(GetProcessHeap(), 0, pAttribs);
            if (FALSE == bSuccess)
            {
                printf("HeapFree failed:%d\n", GetLastError());
                return -6;
            }
        }
        return -104;
    }

    bSuccess = UpdateProcThreadAttribute(pAttribs, 0,
        PROC_THREAD_ATTRIBUTE_PREFERRED_NODE,
        &iNuma, sizeof(iNuma), NULL, NULL);
    if (FALSE == bSuccess)
    {
        printf("UpdateProcThreadAttribute failed:%d\n", GetLastError());
        if (NULL != pAttribs)
        {
            DeleteProcThreadAttributeList(pAttribs);
            bSuccess = HeapFree(GetProcessHeap(), 0, pAttribs);
            if (FALSE == bSuccess)
            {
                printf("HeapFree failed:%d\n", GetLastError());
                return -6;
            }
        }
        return -105;
    }

    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = pAttribs;

    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = /*SW_MINIMIZESW_HIDE; //*/ SW_SHOW;



    sprintf_s(sCommand, 512, "%s  -n %d", m_strExePath.c_str(), m_dwProcessIndex);
    BOOL bRet = CreateProcessA(
        m_strExePath.c_str(),
        &sCommand[0],
        NULL, NULL, TRUE,
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP| EXTENDED_STARTUPINFO_PRESENT,// CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi);
    if (FALSE == bRet)
    {
        printf(" create failed error:%d--processNO:%d\n", GetLastError(), m_dwProcessIndex);
        return 101;
    }
    printf("启动console进程成功index：%d--processID:%d \n", m_dwProcessIndex, pi.dwProcessId);
    CloseHandle(pi.hThread);
    m_hSolverProcess = pi.hProcess;
    m_dwSovlerProcessID = pi.dwProcessId;
    return 0;
}


DWORD CResolverPipe::ThreadProcMonitorProcess()
{

    int iRet = 0;
    HANDLE  hWait[2] = { 0 };
    int     nIndex = 0;
	if (m_strExePath.empty())
	{
		printf(" create Process m_strExePath is empty");
		return 101;
	}
    iRet = StartResolverProcess();
	if ( 0  != iRet)
	{
		printf(" create failed error:%d--processNO:%d\n", GetLastError(), m_dwProcessIndex);
		return 101;
	}

	m_dwProcessState = STATE_PROCESS_START;
	hWait[0] = m_hEventStop;
	hWait[1] = m_hSolverProcess;
	while (m_bRun)
	{
         nIndex = WaitForMultipleObjects(2, hWait, FALSE, INFINITE);
        if (nIndex == WAIT_OBJECT_0 )
        {
            printf(" WaitForMultipleObjects stop--processNO:%d\n",  m_dwProcessIndex);
            CloseHandle(hWait[1]);
            break;
        }
        else if (nIndex == (WAIT_OBJECT_0 +1) )
        {
            printf(" 进程退出index：%d-任务状态：%d-processID:%d \n", m_dwProcessIndex, m_dwProcessState, m_dwSovlerProcessID);
            CloseHandle(hWait[1]);
            if (STATE_PROCESS_START == m_dwProcessState )
            {
                Sleep(2000);
                m_dwReCreateProcessCount++;
            }
            if (m_dwReCreateProcessCount > 20)
            {
                printf(" 子进程连续启动超过20次,都异常退出 \n");
                break;
            }
            m_dwProcessState = STATE_PROCESS_START;

            iRet = StartResolverProcess();
            if (0 != iRet)
            {
                printf(" create failed error:%d--processNO:%d\n", GetLastError(), m_dwProcessIndex);
                return 101;
            }
            m_dwProcessState = STATE_PROCESS_START;
            hWait[1] = m_hSolverProcess;
        }
        else
        {
            printf(" WaitForMultipleObjects failed error:%d--processNO:%d\n", GetLastError(), m_dwProcessIndex);
            m_bRun = FALSE;
        }
	}
	return 0;
}

int CResolverPipe::ReopenWritePipe()
{
    char cName_pipe_Write[256] = { 0 };
    if (INVALID_HANDLE_VALUE == m_hPipeWrite)
    {
        return -1;
    }
    printf(TEXT("ReopenWritePipe start--%d\n"), m_dwProcessIndex);
   BOOL  bRet = FlushFileBuffers(m_hPipeWrite);
    if (!bRet)
    {
        printf(TEXT("FlushFileBuffers write failed , error=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
    }
    bRet = DisconnectNamedPipe(m_hPipeWrite);
    if (!bRet)
    {
        printf(TEXT("DisconnectNamedPipe write failed , error=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
    }
    CloseHandle(m_hPipeWrite);
    m_hPipeWrite = INVALID_HANDLE_VALUE;
    printf(TEXT("ReopenWritePipe finished--%d\n"), m_dwProcessIndex);

    sprintf_s(cName_pipe_Write, 256, "%s_%s_%d", NAME_PIPE_PREFIX, NAME_PIPE_WRITE_PREFIX, m_dwProcessIndex);

    m_hPipeWrite = CreateNamedPipeA(
        cName_pipe_Write,             // pipe name 
        PIPE_ACCESS_DUPLEX,       // read/write access //PIPE_ACCESS_OUTBOUND
        PIPE_TYPE_MESSAGE |       // message type pipe 
        PIPE_READMODE_MESSAGE |   // message-read mode 
        PIPE_WAIT,                // blocking mode 
        PIPE_UNLIMITED_INSTANCES, // max. instances  
        4096,                  // output buffer size 
        4096,                  // input buffer size 
        100000,                        // client time-out 
        NULL);                    // default security attribute 
    if (m_hPipeWrite == INVALID_HANDLE_VALUE)
    {
        printf(TEXT("CreateNamedPipe wrtie failed, GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
        return -2;
    }
    printf("ReopenWritePipe successed--%d\n", m_dwProcessIndex);
    return 0;

}

int CResolverPipe::ReadPipeProc()
{
    BOOL  fSuccess = FALSE;
    DWORD cbBytesRead = 0;
    BOOL   fConnected = FALSE;
    BOOL bRet = FALSE;
    BOOL  bNeedReinitPipe = FALSE;
    int   iRet = 0;
    PIPE_MSG_SATUS msgPipe = { 0 };
    if (m_hPipeRead == INVALID_HANDLE_VALUE)
    {
         printf(TEXT(" ReadPipeProc：m_hPipe == INVALID_HANDLE_VALUE--%d\n"),  m_dwProcessIndex);
        return -1;
    }


   
   while ( m_bRun)
   {

       m_bCanDisconnectPipe = FALSE;
       if (TRUE == bNeedReinitPipe)
       {
           ClosePipe();
            iRet = InitPipe();
           if (0 != iRet)
           {
               printf(" Init Pipe failed:%d --Proecess:%d\n", iRet, m_dwProcessIndex);
               break;
           }
       }
       fConnected = ConnectNamedPipe(m_hPipeRead, NULL) ?
           TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
       if (FALSE == fConnected)
       {
           printf(TEXT("ConnectNamedPipe Read failed, GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
           bNeedReinitPipe = TRUE;
           continue;
       }
       printf(TEXT("ConnectNamedPipe Read successed--%d\n"),  m_dwProcessIndex);
       m_bCanDisconnectPipe = TRUE;
       printf("new client connect--%d\n", m_dwProcessIndex);
       for (;;)
       {
           ZeroMemory(&msgPipe, sizeof(msgPipe));
           cbBytesRead = 0;
           fSuccess = ReadFile(
               m_hPipeRead,        // handle to pipe 
               &msgPipe,    // buffer to receive data 
               sizeof(msgPipe), // size of buffer 
               &cbBytesRead, // number of bytes read 
               NULL);        // not overlapped I/O 

           if (!fSuccess || cbBytesRead == 0)
           {
               if (GetLastError() == ERROR_BROKEN_PIPE)
               {
                   printf(TEXT("InstanceThread: client disconnneect  , GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
               }
               else
               {
                   printf(TEXT("InstanceThread ReadFile failed , GLE=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
 
               }
               bRet = DisconnectNamedPipe(m_hPipeRead);
               if (!bRet)
               {
                   printf(TEXT("DisconnectNamedPipe Read failed , error=%d.--%d\n"), GetLastError(), m_dwProcessIndex);
               }
               iRet = ReopenWritePipe();
               if (0 != iRet)
               {
                   bNeedReinitPipe = TRUE;
               }
               break;
           }
           switch (msgPipe.dwMsgType)
           {
           case PIPEMSG_ITERATION:
           {
               m_nIterationNum = msgPipe.dwIteration;
               m_dwProcessState = STATE_PROCESS_RUNNING;
               break;
           }
           case PIPEMSG_EXPLOIT:
           {
               m_dExploit = msgPipe.dExploit;
               m_dwProcessState = STATE_PROCESS_RUNNING;
               break;

           }
           case  PIPEMSG_READY:
           {
			   m_dwProcessState = STATE_PROCESS_READY;
               m_dwReCreateProcessCount = 0;
               printf("resolve is ready:%d \n", m_dwProcessIndex);
			   if (TRUE == m_bNeedReRuntask)
			   {
				   if (!m_stringConfigFile.empty())
				   {
                       if (m_dwRetryCount < 3)
                       {
                           int iRet = ReRunTask();
                           m_dwRetryCount++;
                           printf("retry task:%s--trycount:%d-- iRet:%d --total seconds:%d\n", m_strTaskID.c_str(), m_dwRetryCount,iRet, GetTickCount() - m_dwStartTick);
                       }
                       else
                       {
                           m_bNeedReRuntask = FALSE;
                           m_dwRetryCount = 0;
                           printf(" task fail:%s--trycount:%d --total seconds:%d\n", m_strTaskID.c_str(), m_dwRetryCount,GetTickCount() - m_dwStartTick);
                           TaskFail(m_strTaskID);
                       }
				   }
			   }
			   else
			   {
			   }
			   break;
		   }
		   case  PIPEMSG_RUNING:
           {
               m_bNeedReRuntask = TRUE;
               m_nIterationNum = 0;
               m_dExploit = 0;
               m_dwReCreateProcessCount = 0;
               m_dwProcessState = STATE_PROCESS_RUNNING;
               break;
           }
           case  PIPEMSG_TASKFINISHED:
           {
               m_dwProcessState = STATE_PROCESS_FINISHED;
               m_dwFinishedSeconds = GetTickCount() - m_dwStartTick;
               printf("task finshed:%s--trycount:%d-- total Seconds:%d \n", m_strTaskID.c_str(), m_dwRetryCount, m_dwFinishedSeconds);
               if (NULL != g_funTaskFinished)
               {
                   g_funTaskFinished(m_strTaskID);
               }
               m_dwRetryCount = 0;
               m_bNeedReRuntask = FALSE;
               break;
           }
           default:
           {
               printf(" unkown pipe msgtype --%d\n", msgPipe.dwMsgType);
               break;
           }
           }
       }
   }
   return 0;
}

int CResolverPipe::writePipe(char* pBuffer, int iLen)
{
    DWORD cbWritten = 0;
    if (m_hPipeWrite == INVALID_HANDLE_VALUE)
    {
        printf(TEXT(" WritePipeProc：m_hPipe == INVALID_HANDLE_VALUE--%d\n"), m_dwProcessIndex);
        return -1;
    }
    // Write the reply to the pipe. 
    BOOL fSuccess = WriteFile(
        m_hPipeWrite,        // handle to pipe 
        pBuffer,     // buffer to write from 
        iLen, // number of bytes to write 
        &cbWritten,   // number of bytes written 
        NULL);        // not overlapped I/O 

    if (!fSuccess || iLen != cbWritten)
    {
        printf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError());
        return -1;
    }

    return 0;
}


int  CResolverPipe::runTask( string strTaskID, string stringConfigFile)
{
    PIPE_MSG_RUNTASK pipeTask = { 0 };
    if (m_dwProcessState != STATE_PROCESS_READY)
    {
        printf(TEXT(" runTask Process Not Ready--state:%d--process:%d\n"), m_dwProcessState, m_dwProcessIndex);
        return -1;
    }
    m_stringConfigFile = stringConfigFile;
      ZeroMemory(&pipeTask, sizeof(pipeTask));
    pipeTask.dwMsgType = PIPEMSG_NOTIFYTASK;
    strcpy_s(pipeTask.strTaskID, 256, strTaskID.c_str());
    strcpy_s(pipeTask.strConfigPath, 256, stringConfigFile.c_str());
    m_bNeedReRuntask = TRUE;
    int iRet = writePipe( (char*)&pipeTask, sizeof(pipeTask));
    if (0 != iRet)
    {
        printf("  send task to pipe failed process:%d -- %s\n", 
            m_dwProcessIndex, strTaskID.c_str());
        return -2;
    }
    else
    {
        m_strTaskID = strTaskID;
        m_dwProcessState = STATE_PROCESS_SENDTASK;
    }
    m_dwStartTick = GetTickCount();

    return 0;
}

int  CResolverPipe::ReRunTask()
{
    if (m_strTaskID.empty())
    {
        printf("ReRunTask, taskid is empty ");
        return -1;
    }
    if (m_stringConfigFile.empty())
    {
        printf("ReRunTask, task config file is empty ");
        return -1;
    }
    return runTask(m_strTaskID, m_stringConfigFile);
}

int   CResolverPipe::StopServerPipe(BOOL bReadPipe)
{
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int iRet = 0;
	char cName_pipe_Read[256] = { 0 };
	char cName_pipe_Write[256] = { 0 };
	if (1 != m_dwProcessIndex && 2 != m_dwProcessIndex)
	{
		printf(" StopServerPipe invalid process index: %d \n ", m_dwProcessIndex);
		return -1;
	}
	sprintf_s(cName_pipe_Read, 256, "%s_%s_%d", NAME_PIPE_PREFIX, NAME_PIPE_READ_PREFIX, m_dwProcessIndex);
	sprintf_s(cName_pipe_Write, 256, "%s_%s_%d", NAME_PIPE_PREFIX, NAME_PIPE_WRITE_PREFIX, m_dwProcessIndex);


	if (bReadPipe)
	{
		if (WaitNamedPipeA(cName_pipe_Read, NMPWAIT_WAIT_FOREVER) == FALSE)
		{
			printf("  stop pipe WaitNamedPipe failed: %d -- process:%d \n ", GetLastError(), m_dwProcessIndex);
			return -2;
		}
		hPipe = CreateFileA(cName_pipe_Read, GENERIC_WRITE, 0,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	else
	{
		if (WaitNamedPipeA(cName_pipe_Write, NMPWAIT_WAIT_FOREVER) == FALSE)
		{
			printf("  stop pipe WaitNamedPipe failed: %d -- process:%d \n ", GetLastError(), m_dwProcessIndex);
			return -2;
		}
		hPipe = CreateFileA(cName_pipe_Write, GENERIC_READ, 0,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}



	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf(" stop pipe CreateNamedPipe failed, GLE=%d  process: %d \n", GetLastError(), m_dwProcessIndex);
		return -3;
	}
	//DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	hPipe = INVALID_HANDLE_VALUE;
	return 0;
}

void  CResolverPipe::ClosePipe()
{
    if (m_hPipeWrite != INVALID_HANDLE_VALUE)
    {
        printf(" ClosePipe-write--%d\n", m_dwProcessIndex);
        if (TRUE == m_bCanDisconnectPipe)
        {
            DisconnectNamedPipe(m_hPipeWrite);
        }
        else
        {
            StopServerPipe(FALSE);
            DisconnectNamedPipe(m_hPipeWrite);
        }
        CloseHandle(m_hPipeWrite);
        m_hPipeWrite = INVALID_HANDLE_VALUE;
        printf(" write pipe:%d closed\n", m_dwProcessIndex);
    }
    if (m_hPipeRead != INVALID_HANDLE_VALUE)
    {
        printf(" ClosePipe-read--%d\n", m_dwProcessIndex);
        if (TRUE == m_bCanDisconnectPipe)
        {
            DisconnectNamedPipe(m_hPipeRead);
        }
        else
        {
            StopServerPipe(TRUE);
            DisconnectNamedPipe(m_hPipeRead);
        }
        CloseHandle(m_hPipeRead);
        m_hPipeRead = INVALID_HANDLE_VALUE;
        printf(" read pipe:%d closed\n", m_dwProcessIndex);
    }


}