
#include <windows.h>
#include <string>

#pragma once

using namespace std;
#define PIPEMSG_ITERATION 1
#define PIPEMSG_EXPLOIT 2
#define PIPEMSG_READY  3
#define PIPEMSG_RUNING 4
#define PIPEMSG_TASKFINISHED 5
#define PIPEMSG_NOTIFYTASK 6

#pragma pack(push,1)
typedef struct
{
	DWORD dwMsgType;
	DWORD dwIteration;
	double dExploit;
}PIPE_MSG_SATUS, *LPPIPE_MSG_SATUS;

typedef struct
{
	DWORD dwMsgType;
	char  strTaskID[256];
	char  strConfigPath[256];
}PIPE_MSG_RUNTASK, *LPPIPE_MSG_RUNTASK;
#pragma pack(pop)

typedef enum _PEOCESS_STATE
{
	STATE_PROCESS_START = 1,
	STATE_PROCESS_READY = 2,
	STATE_PROCESS_RUNNING = 3,
	STATE_PROCESS_FINISHED= 4,
	STATE_PROCESS_STOPPED = 5
}STATE_PROCESS;

typedef void (*FuncTaskFinish)(const string&);

class  CResolverPipe
{
public:
	 CResolverPipe();
	virtual ~CResolverPipe();
	int  InitPipe();
	int  ReadPipeProc();
	int writePipe(char* pBuffer, int iLen);
	void  ClosePipe();
	int  runTask(string strTaskID, string stringConfigFile);
	int  ReRunTask();
	DWORD ThreadProcMonitorProcess();
	DWORD Start(int dwProcessIndex);
	int   StopServerPipe(BOOL bReadPipe);
	int   ReopenWritePipe();
	void SetExePath(string strExePath)
	{
		m_strExePath = strExePath;
	};
	void Stop()
	{
		m_bRun = false;
		ClosePipe();
		if (INVALID_HANDLE_VALUE != m_hEventStop)
		{
			SetEvent(m_hEventStop);
		}
	};
	STATE_PROCESS GetState()
	{
		return m_dwProcessState;
	};
	string GetCurTaskID()
	{
		return m_strTaskID;
	};
	DWORD GetIterration()
	{
		return m_nIterationNum;
	};

	double GetExploit()
	{
		return m_dExploit;
	};
	DWORD GetConitunedSeconds()
	{
		if (STATE_PROCESS_RUNNING == m_dwProcessState)
		{
			return m_dwFinishedSeconds;
		}
		else
		{
			return GetTickCount() - m_dwStartTick;
		}
	};
private:
	DWORD m_dwRetryCount;
	DWORD m_dwReCreateProcessCount;
	DWORD m_nIterationNum;
	double m_dExploit;

	DWORD m_dwStartTick;
	DWORD m_dwFinishedSeconds;
	DWORD m_dwProcessIndex;
	string  m_strTaskID;
	string m_stringConfigFile;
	HANDLE m_hPipeRead;
	HANDLE m_hPipeWrite;
	BOOL  m_bRun;
	STATE_PROCESS m_dwProcessState;
	string m_strExePath;
	HANDLE m_hEventStop;
	BOOL m_bNeedReRuntask;
	BOOL m_bCanDisconnectPipe;
};