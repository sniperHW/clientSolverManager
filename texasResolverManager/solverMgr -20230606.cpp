// texasResolverManager.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。

#include<winsock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <math.h>
#include <memoryapi.h>

#include  "rpipe.h"

#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib, "Mpr.lib")

using namespace std;

typedef struct _TASKINFO
{
    string sCurTaskID;
    int nContinuedSeconds; //单位，毫秒
    int nIterationNum;
    double dExploit;
    BOOL bFinished;
}TASKINFO, *LPTASKINFO;

CResolverPipe g_pipeMgr[2];

extern FuncTaskFinish g_funTaskFinished;

#define NUM_PROCESS_1  1
#define NUM_PROCESS_2  2

DWORD g_dwResolverNum = 1;

vector<string> string_split(string strin,char split){
    vector<string> retval;
    stringstream ss(strin);
    string token;
    while (getline(ss,token, split))
    {
        retval.push_back(token);
    }
    return retval;
}

string GetCurrentPath()
{
    char   exeFullPath[MAX_PATH];   
    GetModuleFileNameA(NULL,exeFullPath,MAX_PATH);
    string csCurrentPath = exeFullPath;
    size_t pos = csCurrentPath.find("\\");
    size_t totalpos;
    while(pos != std::string::npos)
    {
        pos++;
        totalpos = pos;
        pos = csCurrentPath.find("\\",pos);
    }
    csCurrentPath = csCurrentPath.substr(0,totalpos);
    return csCurrentPath;
} 

string g_sComputerName;
string g_sLocalIP;
DWORD g_dwMemSize = 0;

void GetSytemInfo()
{
    char Buf[256] = { 0 };
    ZeroMemory(Buf, sizeof(Buf));
    DWORD dwSize = sizeof(Buf);
     BOOL bRet =  GetComputerNameA(Buf, &dwSize);
     if (bRet)
     {
         printf(" computerName:%s \n", Buf);
         g_sComputerName = Buf;
     }
     _MEMORYSTATUSEX  msEx;
         msEx.dwLength = sizeof(msEx);
    bRet =  ::GlobalMemoryStatusEx(&msEx);
    if (bRet)
    {
        g_dwMemSize = (DWORD)(msEx.ullTotalPhys / (1024 * 1024));
        printf("mem size:%d \n", g_dwMemSize);
    }

    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    //初始化socket环境
    if (::WSAStartup(sockVersion, &wsaData) != 0)
    {
        return;
    }

    //获得主机名称
    char szHost[256] = { 0 };
    ::gethostname(szHost, 256);
    printf("主机名=%s", szHost);
    //获得主机名称下的网络信息
    hostent* pHost = ::gethostbyname(szHost); //返回指定主机名的包含主机名字和地址信息的hostent结构的指针
 
    //处理获得的网络信息
    in_addr addr;
    string strIP;
    for (int i = 0;; i++)
    {
        char* p = pHost->h_addr_list[i];
        if (p == NULL)
            break;
        memcpy(&addr.S_un.S_addr, p, pHost->h_length);
        char* slzp = ::inet_ntoa(addr); 
        strIP = slzp;
        strIP.append( "|");
        g_sLocalIP.append(strIP);
    }
    ::WSACleanup();
    printf(" local ip:%s \n", g_sLocalIP.c_str());
}

void getState(string& sComputerName, string& sIP, int& nMemSize, vector<TASKINFO>& taskInfos)
{
    sComputerName = g_sComputerName;
    sIP = g_sLocalIP;
    nMemSize = g_dwMemSize;
    TASKINFO   _taskState;

    for (int i = 0; i < 2; i++)
    {
        _taskState.sCurTaskID = "";
        ZeroMemory(&_taskState, sizeof(_taskState));
        _taskState.sCurTaskID = g_pipeMgr[i].GetCurTaskID();

        if (_taskState.sCurTaskID.empty())
        {
            continue;
        }
        _taskState.nIterationNum = g_pipeMgr[i].GetIterration();
        _taskState.dExploit = g_pipeMgr[i].GetExploit();
        _taskState.nContinuedSeconds = g_pipeMgr[i].GetConitunedSeconds();
        if (STATE_PROCESS_RUNNING == g_pipeMgr[i].GetState())
        {
            _taskState.bFinished = FALSE;
        }
        else
        {
            _taskState.bFinished = TRUE;
        }
        taskInfos.emplace_back(_taskState);
    }
}

void SetTaskFiniedCallback(FuncTaskFinish callback)
{
	g_funTaskFinished = callback;
}


int toSolve(const string& sTaskID, const string& sConfigPath)
{
    //如果已经有任务在执行，返回
    if (1 == g_dwResolverNum)
    {
        if (STATE_PROCESS_RUNNING == g_pipeMgr[0].GetState()
            && STATE_PROCESS_RUNNING == g_pipeMgr[1].GetState())
        {
            printf(" two resolvers are running \n");
            return  -1;
        }
    }
    else
    {
        for (int i = 0; i < 2; i++)
        {
            if (STATE_PROCESS_RUNNING == g_pipeMgr[i].GetState())
            {
                printf(" no ready already one task is runing\n");
                return  -1;
            }
        }
    }

    for (int k = 0; k < 50; k++)
    {
        for (int i = 0; i < 2; i++)
        {
            if (STATE_PROCESS_READY == g_pipeMgr[i].GetState())
            {
                g_pipeMgr[i].runTask(sTaskID, sConfigPath);
                return 0;
            }
        }
        Sleep(200);
    }
    printf(" new task  no ready process \n");
    return -2;
}

int AccessShareFolder(const char* szUserName, const char* szPasswd, const char* lpRemotePath)
{
    int iRet = -1;
    NETRESOURCE net_Resource;
    net_Resource.dwDisplayType = RESOURCEDISPLAYTYPE_DIRECTORY;
    net_Resource.dwScope = RESOURCE_CONNECTED;
    net_Resource.dwType = RESOURCETYPE_DISK | RESOURCETYPE_ANY;// RESOURCETYPE_ANY;
    net_Resource.dwUsage = 0;
    char szComment[] = "";
    net_Resource.lpComment = &szComment[0];
    char szLocalDrive[] = "z:";
    net_Resource.lpLocalName = szLocalDrive;  //映射成本地驱动器z:
    net_Resource.lpProvider = NULL;
    net_Resource.lpRemoteName = const_cast<char*>(lpRemotePath);// TEXT("\\\\192.168.0.2\\管理部"); // \\servername\共享资源名
    DWORD dwFlags = CONNECT_UPDATE_PROFILE | CONNECT_INTERACTIVE | CONNECT_COMMANDLINE | CONNECT_CMD_SAVECRED;// CONNECT_UPDATE_PROFILE;
    DWORD dw = WNetAddConnection3A(NULL, &net_Resource, szPasswd, szUserName, dwFlags);
    switch (dw)
    {
    case ERROR_SUCCESS:
        // ShellExecute(NULL, TEXT("open"), TEXT("z:"), NULL, NULL, SW_SHOWNORMAL);
        printf(TEXT("共享目录访问成功！"));
        iRet = 0;
        break;
    case ERROR_ACCESS_DENIED:
        printf(TEXT("没有权访问！"));
        iRet = -2;
        break;
    case ERROR_ALREADY_ASSIGNED:
        // ShellExecute(NULL, TEXT("open"), TEXT("z:"), NULL, NULL, SW_SHOWNORMAL);
        iRet = 0;
        break;
    case ERROR_INVALID_ADDRESS:
        printf(TEXT("IP地址无效"));
        iRet = -3;
        break;
    case ERROR_NO_NETWORK:
        printf(TEXT("网络不可达!"));
        iRet = -4;
        break;
    case ERROR_BAD_DEV_TYPE:
        printf(TEXT("设备不匹配"));
        iRet = -5;
        break;
    case ERROR_BAD_NET_NAME:
        printf(TEXT("远程路径不可访问"));
        iRet = -6;
        break;
    default:
        iRet = -101;
        break;
    }
    return iRet;
}
int InitSharePath()
{
    int iRet = -1;
    char cBuf[256] = { 0 };
    string sCurPath = GetCurrentPath();
    string sConfigFile = sCurPath + "updateConfig.ini";

    // share path
    DWORD dwRet = GetPrivateProfileStringA("updateserver", "sharePath", "",
        cBuf, 256, sConfigFile.c_str());
    if (dwRet < 2)
    {
        printf("get update config failed:%d\n", GetLastError());
        return -1;
    }
    string sServerSharePath = cBuf;

    //username
    ZeroMemory(cBuf, sizeof(cBuf));
    dwRet = GetPrivateProfileStringA("updateserver", "username", "",
        cBuf, 256, sConfigFile.c_str());
    if (0 == dwRet)
    {
        printf("get username failed:%d\n", GetLastError());
        return -3;
    }
    string sNetUsername = cBuf;

    //pathword

    ZeroMemory(cBuf, sizeof(cBuf));
    dwRet = GetPrivateProfileStringA("updateserver", "password", "",
        cBuf, 256, sConfigFile.c_str());
    if (0 == dwRet)
    {
        printf("get username failed:%d\n", GetLastError());
        return -3;
    }
    string sPassword = cBuf;

    //确认网络共享是否可以访问
    iRet = AccessShareFolder(sNetUsername.c_str(), sPassword.c_str(), sServerSharePath.c_str());
    if (0 != iRet)
    {
        printf("acess share remote path failed:%d--%d\n", iRet, GetLastError());
        return -4;
    }
    return 0;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL  RebootCopmuter()
{
    HANDLE hToken;
    BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    bRet = SetPrivilege(hToken, SE_SHUTDOWN_NAME, TRUE);
    if (!bRet)
    {
        printf(" set Privilege failed \n");
        return FALSE;
    }

    bRet = ExitWindowsEx(EWX_REBOOT | /*EWX_FORCEIFHUNG*/EWX_FORCE, SHTDN_REASON_MAJOR_OTHER);
    if (FALSE == bRet)
    {
        printf(" reboot failed\n");
    }
    else
    {
        printf(" reboot ...\n");
    }
    return bRet;
}

#define BUF_SIZE  64*1024
 int copyFile_winAPI(const string& srcFile, const string& desFilePath)
{
HANDLE hIn, hOut;
DWORD dwIn, dwOut;
TCHAR Data[BUF_SIZE];
DWORD dwLen = 0;



hIn = CreateFileA(srcFile.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
if (INVALID_HANDLE_VALUE == hIn)
{
    printf("Can't open open file %s : %x\n",
        srcFile.c_str(), GetLastError());
    return 2;
}

hOut = CreateFileA(desFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL, NULL);
if (INVALID_HANDLE_VALUE == hOut)
{
    printf("Can't open file : %s: %x\n",
        desFilePath.c_str(), GetLastError());
    return 3;
}

while (ReadFile(hIn, Data, BUF_SIZE, &dwIn, NULL) > 0)
{
    WriteFile(hOut, Data, dwIn, &dwOut, NULL);
    if (dwIn != dwOut)
    {
        printf("Fatal Error: %x\n", GetLastError());
        return 4;
    }
    dwLen += dwIn;
    printf("Copying file .... %d bytes copy\n", dwLen);
}

CloseHandle(hIn);
CloseHandle(hOut);

return 0;
}
//desFilePath为共享文件内的相对路径
int  upLoadResult(const string& srcFilePath, const string& desFilePath)
{
    string  strDestFile = "z:\\" + desFilePath;
   // int iRet = copyFile_winAPI(srcFilePath, strDestFile);

    if (!CopyFileA(srcFilePath.c_str(), strDestFile.c_str(), FALSE))
    {
        printf("Copy file error : %x\n", GetLastError());
        return -1;
    }

    return 0;
}
void usage()
{
    printf("i--input the task id \n");
    printf("f--input the Input file(fullpath) \n");
    printf("r--run the task \n");
    printf("t--GetState \n");
    printf("s--source file to be uploaded for result \n");
    printf("d--dest file to be uploaded for result \n");
    printf("u--upload result file \n");
    printf("x--exit this applicatipn\n");
    printf("b--reboot system \n");
    printf("h--help \n");
}

int main()
{
    DBG_CONTROL_BREAK;

    GetSytemInfo();

    string sPath = GetCurrentPath();
    printf("current path is :%s \n", sPath.c_str());

    string sConfigFile = sPath + "resolvermanager.ini";

    // share path
    DWORD dwRet = GetPrivateProfileIntA("control", "processtype",
        1, sConfigFile.c_str());
    if (2 == dwRet)
    {
       g_dwResolverNum = 2;
    }
    else
    {
        g_dwResolverNum = 1;
    }
    printf("max resolve process allowed is :%d\n", g_dwResolverNum);
    printf("current path is :%s \n", sPath.c_str());
    string sExe1 = sPath + "ResolverTest.exe";
    printf("current tesxas console exe is :%s \n", sExe1.c_str());

    g_pipeMgr[0].SetExePath(sExe1);
    g_pipeMgr[0].Start(1);

    g_pipeMgr[1].SetExePath(sExe1);
    g_pipeMgr[1].Start(2);

    usage();
    int ch = 0;
    BOOL bRun = TRUE;
    string strTaskID;
    string strInputFile;
    string strSourceResolvedResultedFile;
    string strDestFileUploaded;

    while (bRun)
    {
        printf(" please input a command (h,d,i,r,x):\n");
        ch = getchar();
        switch (ch)
        {
        case 'h':
        case 'H':
        {
            usage();
            break;
        }
        case 'i': //set taskID for task
        case 'I':
        {
            printf(" please input task ID:\n");
            getline(cin, strTaskID);
            printf("you input for task ID is:%s\n", strTaskID.c_str());
            break;
        }
        case 'f': //inputfile for task
        case 'F':
        {
            printf(" please input the full path of input file:\n");
            getline(cin, strInputFile);
            printf(" your input for  input File  is:%s\n", strInputFile.c_str());
            break;
        }
        case 'r': //run task
        case 'R':
        {
            if (strTaskID.empty())
            {
                printf(" error-- task ID is empty\n");
                usage();
                break;
            }
            if (strInputFile.empty())
            {
                usage();
                printf(" error-- input File is empty\n");
                break;
            }
            while (1)
            {
                printf(" task ID is:%s\n", strTaskID.c_str());
                printf("  input File  is:%s\n", strInputFile.c_str());
                printf("  print y to run the task and n to modify taskid or input file, y or n\n");
                ch = getchar();
                if ('y' == ch || 'Y' == ch)
                {
                    toSolve(strTaskID, strInputFile);
                    strTaskID = "";
                    strInputFile = "";
                }
                else if ('n' == ch || 'N' == ch)
                {
                    break;
                }
                else
                {

                }
            }

            break;
        }
        case 's': //set taskID for task
        case 'S':
        {
            printf(" please input source  file for the resolved result to be uploaded:\n");
            getline(cin, strSourceResolvedResultedFile);
            printf("you input for task ID is:%s\n", strSourceResolvedResultedFile.c_str());
            break;
        }
        case 'd': // dest file to upoaded .relative path
        case 'D':
        {
            printf(" please input the full path of input file:\n");
            getline(cin, strDestFileUploaded);
            printf(" your input for  input File  is:%s\n", strDestFileUploaded.c_str());
            break;
        }
        case 'u': //upLoad
        case  'U':
        {
            string strSourceResolvedResultedFile;
            string strDestFileUploaded;

            if (strSourceResolvedResultedFile.empty())
            {
                printf(" error-- source file name is  empty\n");
                usage();
                break;
            }
            if (strDestFileUploaded.empty())
            {
                usage();
                printf(" error-- dest File is empty\n");
                break;
            }
            while (1)
            {
                printf(" source file is:%s\n", strSourceResolvedResultedFile.c_str());
                printf("  dest filename  is:%s\n", strDestFileUploaded.c_str());
                printf("  print y to upload the specified file , y or n\n");
                ch = getchar();
                if ('y' == ch || 'Y' == ch)
                {
                    upLoadResult(strSourceResolvedResultedFile, strDestFileUploaded);
                    strSourceResolvedResultedFile = "";
                    strDestFileUploaded = "";
                }
                else if ('n' == ch || 'N' == ch)
                {
                    break;
                }
                else
                {

                }
            }
            break;
        }
        
        case 't'://Get state
        case 'T':
        {
            string sComputerName;
            string sIP;
            int   nMemSize;
            vector<TASKINFO> taskInfos;
            getState(sComputerName, sIP, nMemSize, taskInfos);
            printf("computname is:%s \n", sComputerName.c_str());
            printf(" Local ip is:%s \n", sIP.c_str());
            printf(" memsize is:%d MB \n", nMemSize);
            printf(" current task count is:%zd \n", taskInfos.size());
            for (int k = 0; k < taskInfos.size(); k++)
            {
                TASKINFO taskState = taskInfos.at(k);
                printf("task ID is:%s \n", taskState.sCurTaskID.c_str());
                printf(" is task finished:%d \n", taskState.bFinished);
                printf("task nIteration Numbwr:%d \n", taskState.nIterationNum);
                printf(" task continued milliseconds :%d \n", taskState.nContinuedSeconds);
                printf(" task exploit:%f \n", taskState.dExploit);
                printf(" ----------------------- \n");
            }

            break;
        }
        case 'x': //exit
        case 'X':
        {
            printf("exit \n");
            bRun = FALSE;
            break;
        }
        case 'b': //reboot
        case 'B':
        {
            RebootCopmuter();
            break;
        }
        default:
        {
            usage();
            printf(" unkown command:%c\n", ch);
            break;
        }

        }
    }
    g_pipeMgr[0].Stop();
    g_pipeMgr[1].Stop();
}


