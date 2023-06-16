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
#include <mutex>
#include <condition_variable>
#include <filesystem>
//namespace fs = std::filesystem;

#include "json.hpp"
#include "net.h"

#include  "rpipe.h"

#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib, "Mpr.lib")

using namespace std;
using json = nlohmann::json;

typedef struct _TASKINFO
{
    string sCurTaskID;
    int nContinuedSeconds; //单位，毫秒
    int nIterationNum;
    double dExploit;
    BOOL bFinished;

    _TASKINFO() {}


    _TASKINFO(const string& sCurTaskID, int nContinuedSeconds, int nIterationNum, double dExploit) :
        sCurTaskID(sCurTaskID), nContinuedSeconds(nContinuedSeconds), nIterationNum(nIterationNum), dExploit(dExploit) {}


}TASKINFO, *LPTASKINFO;

CResolverPipe g_pipeMgr[2];

extern FuncTaskFinish g_funTaskFinished;

#define NUM_PROCESS_1  1
#define NUM_PROCESS_2  2

DWORD g_dwResolverNum = 1;
int g_nErrorCode = 0;

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

    printf(" local ip:%s \n", g_sLocalIP.c_str());
}

//接口：获取状态信息，nErrorCode非0代表该客户端处于不可用状态，不能分配任务，任务全部结束后taskInfos也含有两条记录，这时bFinished=true,
void getState(string& sComputerName, string& sIP, int& nMemSize, int& nErrorCode, vector<TASKINFO>& taskInfos)
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

    nErrorCode = g_nErrorCode; //返回错误码
}


net::NetClient::Ptr g_netClient = nullptr;

enum taskState {
    taskRunning, 
    taskWaitCommit,
    taskFinish,
    taskCancel,
};

struct task {
    std::mutex  mtx;
    std::condition_variable_any cv;
    std::string taskID;
    std::string resultPath;
    taskState   state;
    int         nContinuedSeconds; //单位，毫秒
    int         nIterationNum;
    double      dExploit;

    task():nContinuedSeconds(0), nIterationNum(0), dExploit(0) {

    }

    void setStateAndNotify(taskState state) {
        mtx.lock();
        this->state = state;
        mtx.unlock();
        cv.notify_one();
    }

    taskState getState() {
        std::lock_guard<std::mutex> guard(mtx);
        return state;
    }
};

std::map<std::string, task*> taskMap;
std::mutex taskMapMtx;

net::Buffer::Ptr makeHeartBeatPacket(const std::vector<TASKINFO> &tasks) {
    json j;
    j["WorkerID"] = g_sLocalIP;
    j["Memory"]   = g_dwMemSize / 1024;
    auto Tasks = json::array();

    for (auto it = tasks.begin(); it != tasks.end(); it++) {
        json t;
        t["TaskID"] = (* it).sCurTaskID;
        t["ContinuedSeconds"] = (*it).nContinuedSeconds;
        t["IterationNum"] = (*it).nIterationNum;
        t["Exploit"] = (*it).dExploit;
        Tasks.push_back(t);
    }

    j["Tasks"] = Tasks;

    auto jStr = j.dump();

    auto packet = net::Buffer::New(6 + jStr.length());

    packet->Append(uint32_t(2 + jStr.length()));

    packet->Append(uint16_t(1));

    packet->Append(jStr);

    return packet;

}


void commitTaskRoutine(task* task) {

    //读取result文件

    if (std::ifstream is{ task->taskID + ".json", std::ios::binary | std::ios::ate}) {
        auto size = is.tellg();
        std::string str(size, '\0'); // construct string to stream size
        is.seekg(0);
        if (is.read(&str[0], size))
            std::cout << str << '\n';
    
    
        json j;
        j["TaskID"] = task->taskID;
        j["Result"] = str;

        auto jStr = j.dump();
        auto packet = net::Buffer::New(6 + jStr.length());

        packet->Append(uint32_t(2 + jStr.length()));
        packet->Append(uint16_t(3));
        packet->Append(jStr);

        std::lock_guard<std::mutex> guard(task->mtx);

        //重复提交任务，直到接收到提交成功或任务取消
        for (;;) {
            g_netClient->Send(packet);
            task->cv.wait_for(task->mtx, chrono::seconds(1));//如果没有被唤醒，则等待一秒
            if (task->state == taskCancel || task->state == taskFinish) {
                std::vector<TASKINFO> tasks;
                taskMapMtx.lock();
                taskMap.erase(task->taskID);
                for (auto it = taskMap.begin(); it != taskMap.end(); it++) {
                    tasks.push_back(_TASKINFO(it->second->taskID, it->second->nContinuedSeconds, it->second->nIterationNum, it->second->dExploit));
                }
                taskMapMtx.unlock();

                delete(task);

                g_netClient->Send(makeHeartBeatPacket(tasks));
                return;
            }
        }
    }

}





//接口：任务结束的回调函数，参数为任务ID
void TaskFinish(const string& sTaskID)
{
    cout << "task finish callback " << sTaskID << endl;
    taskMapMtx.lock();
    auto task = taskMap[sTaskID];
    taskMapMtx.unlock();
    if (task == nullptr) {
        //不应该发生
        return;
    }

    task->mtx.lock();
    if (task->state == taskRunning) {
        task->state = taskWaitCommit;
    }
    else {
        task->mtx.unlock();
        return;
    }
    task->mtx.unlock();
    
    //启动提交routine,
    auto _ = std::thread(commitTaskRoutine,task);

}

void SetTaskFiniedCallback(FuncTaskFinish callback)
{
	g_funTaskFinished = callback;
}



//接口：执行解算任务
int toSolve(const string& sTaskID, const string& sConfigPath)
{
    //如果已经有任务在执行，返回
    if (1 == g_dwResolverNum)
    {
        if (STATE_PROCESS_RUNNING == g_pipeMgr[0].GetState()
             || STATE_PROCESS_RUNNING == g_pipeMgr[1].GetState())
        {
            printf(" one resolver allowed and there is one  resolvers   running already, \n");
            return  -1;
        }
    }
    else
    {
        if (STATE_PROCESS_RUNNING == g_pipeMgr[0].GetState()
            &&  STATE_PROCESS_RUNNING == g_pipeMgr[1].GetState())
        {
            printf(" two resolvers  allowed and the two resolver are both running \n");
            return  -1;
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
        Sleep(1000);
        printf(" wait for process ready : %d seonds--of total 50 seconds \n",k);
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
        printf(TEXT("共享目录访问成功！\n"));
        iRet = 0;
        break;
    case ERROR_ACCESS_DENIED:
        printf(TEXT("没有权访问！\n"));
        iRet = -2;
        break;
    case ERROR_ALREADY_ASSIGNED:
        // ShellExecute(NULL, TEXT("open"), TEXT("z:"), NULL, NULL, SW_SHOWNORMAL);
        iRet = 0;
        break;
    case ERROR_INVALID_ADDRESS:
        printf(TEXT("IP地址无效 \n"));
        iRet = -3;
        break;
    case ERROR_NO_NETWORK:
        printf(TEXT("网络不可达!\n"));
        iRet = -4;
        break;
    case ERROR_BAD_DEV_TYPE:
        printf(TEXT("设备不匹配"));
        iRet = -5;
        break;
    case ERROR_BAD_NET_NAME:
        printf(TEXT("远程路径不可访问\n"));
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

//接口：上传解算结果，desFilePath为共享文件内的相对路径
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

    printf("runtask taskID inputfile -- to run a task \n");
    printf("upload sourcefile destfile-- to upload the resolved result sourcefile to destfile  \n");
    printf("t|getstate)-- get the current task state\n");
    printf("x|exit)--exit this applicatipn\n");
    printf("r|reboot)-- reboot system \n");
    printf("h|help--help \n");
}

/*
bool copyCfgFile(const std::string& path, const std::string& taskID) {
    std::ifstream infile;
    infile.open("z:\\" + path);
    if (!infile.is_open()) {
        return false;
    }

    std::vector<std::string> lines;

    bool ok = true;


    std::string s;
    while (getline(infile, s)) {
        if (s.find("dump")) {
            ok = true;
            lines.push_back("dump " + taskID + ".json");
        }
        else {
            lines.push_back(s);
        }
    }

    infile.close();

    if (!ok) {
        return false;
    }


    std::ofstream ofs;
    ofs.open(taskID, std::ios::out);
    for (auto it = lines.begin(); it != lines.end(); it++) {
        ofs << *it << std::endl;
    }
    ofs.close();

    return true;
}*/


void onPacket(const net::Buffer::Ptr& packet) {
    auto rawBuf = packet->BuffPtr();
    auto cmd = ::ntohs(*(uint16_t*)rawBuf);
    auto jsonStr = std::string(&rawBuf[2], packet->Len() - 2);
    auto msg = json::parse(jsonStr);

    switch (cmd) {
    case 2: {//CmdDispatchJob
            auto taskID = msg["TaskID"].get<std::string>();
            auto CfgPath = msg["TaskID"].get<std::string>();
            auto ResultPath = msg["TaskID"].get<std::string>();
            taskMapMtx.lock();
            auto t = taskMap[msg["TaskID"].get<std::string>()];
            taskMapMtx.unlock();
            if (t != nullptr) {
                return;
            }

            //将cfg文件复制到本地，并做改写
            /*bool ok = false;
            auto c = 0;
            for (; c < 3; c++) {
                ok = copyCfgFile(CfgPath, taskID);
                if (!ok) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }

            if (!ok) {
                return;
            }*/


            std::ofstream ofs;
            ofs.open(taskID, std::ios::out);
            ofs << msg["Cfg"].get<std::string>();
            ofs.close();


            toSolve(taskID, taskID);
            
            t = new task();
            t->taskID = taskID;
            t->resultPath = ResultPath;
            t->state = taskRunning;


            std::vector<TASKINFO> tasks;
            taskMapMtx.lock();
            taskMap[taskID] = t;
            for (auto it = taskMap.begin(); it != taskMap.end(); it++) {
                tasks.push_back(_TASKINFO(it->second->taskID, it->second->nContinuedSeconds, it->second->nIterationNum, it->second->dExploit));
            }
            taskMapMtx.unlock();
            g_netClient->Send(makeHeartBeatPacket(tasks));
        }
        break;
    case 4://CmdAcceptJobResult = uint16(4)
    case 5: {//CmdCancelJob       = uint16(5)
            

            auto taskID = msg["TaskID"].get<std::string>();
            
            //删除本地文件
            std::filesystem::remove(taskID); //cfg文件
            std::filesystem::remove(taskID+".json");//结果文件
            
        
        
        
            taskMapMtx.lock();
            auto task = taskMap[taskID];
            taskMapMtx.unlock();
            if (task != nullptr) {
                if (cmd == 4) {
                    task->setStateAndNotify(taskFinish);
                }
                else {
                    task->setStateAndNotify(taskCancel);
                }
            }
        }
        break;
    }
}

void heartbeatRoutine() {

    for (;;) {
        string sComputerName;
        string sIP;
        int   nMemSize;
        int nErrorCode;
        vector<TASKINFO> taskInfos;
        getState(sComputerName, sIP, nMemSize, nErrorCode, taskInfos);

        vector<TASKINFO> tasks;

        taskMapMtx.lock();
        for (auto it = taskInfos.begin(); it != taskInfos.end(); it++) {
            auto it_ = taskMap.find(it->sCurTaskID);
            if (it_ != taskMap.end()) {
                it_->second->nContinuedSeconds = it->nContinuedSeconds;
                it_->second->nIterationNum = it->nIterationNum;
                it_->second->dExploit = it->dExploit;
            }
        }

        for (auto it = taskMap.begin(); it != taskMap.end(); it++) {
            tasks.push_back(_TASKINFO(it->second->taskID, it->second->nContinuedSeconds, it->second->nIterationNum, it->second->dExploit));
        }

        taskMapMtx.unlock();

        g_netClient->Send(makeHeartBeatPacket(tasks));

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}


int main(int argc,char **argv)
{

    const char* serverIp = "127.0.0.1";
    u_short serverPort = 18889;


    DBG_CONTROL_BREAK;

    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    //初始化socket环境
    if (::WSAStartup(sockVersion, &wsaData) != 0)
    {
        return -1;
    }


    GetSytemInfo();

    string sPath = GetCurrentPath();
    //printf("current path is :%s \n", sPath.c_str());
    
    //测试时先注释掉
    //g_nErrorCode = InitSharePath();

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
    ::printf("max resolve process allowed is :%d\n", g_dwResolverNum);
    //printf("current path is :%s \n", sPath.c_str());
    string sExe1 = sPath + "console_solver.exe";
    //printf("current tesxas console exe is :%s \n", sExe1.c_str());

    g_pipeMgr[0].SetExePath(sExe1);
    g_pipeMgr[0].Start(1);

    g_pipeMgr[1].SetExePath(sExe1);
    g_pipeMgr[1].Start(2);


    if (argc > 2) {
        serverIp = argv[1];
        serverPort = ::atoi(argv[2]);
    }

    //先连接上服务器
    for (;;) {
        g_netClient = net::NetClient::New(serverIp, serverPort, onPacket);
        if (g_netClient != nullptr) {
            break;
        }
        else {
            ::Sleep(1000);
        }
    }

    //启动心跳

    auto _ = std::thread(heartbeatRoutine);


    int ch = 0;
    BOOL bRun = TRUE;
    string strInput;
    vector<string> vCommands;
    string strCmd;

    SetTaskFiniedCallback(TaskFinish);


    usage(); //命令行测试说明
    while (bRun)
    {




        //以下代码为测试接口用
        printf("(input a command)$>");
        getline(cin, strInput);
        vCommands = string_split(strInput, ' ');
        if (0 == vCommands.size() || vCommands.at(0).empty())
        {
            continue;
        }
        else if (vCommands.size() > 3)
        {
            printf(" no blank in path or paremtered allowed !!! \n");
            string strTemp;
            for (int k = 0; k < vCommands.size(); k++)
            {
                strTemp = vCommands.at(k);
                printf(" comand part %d is %s \n", k, strTemp.c_str());
            }
            continue;
        }
        else if ( 2 == vCommands.size() )
        {
            printf(" command need  two paramter or no paramter|！！！ \n");
            printf(" no blank in path or paremtered allowed !!! \n");
            string strTemp;
            for (int k = 0; k < vCommands.size(); k++)
            {
                strTemp = vCommands.at(k);
                printf(" comand part %d length %zd is %s \n", k+1, strTemp.length(),strTemp.c_str());
            }
             continue;
        }
        strCmd = vCommands.at(0);
        if (1 == vCommands.size())
        {
            if ("h" == strCmd || "help" == strCmd)
            {
                usage();
            }
            else if   ("x" == strCmd || "exit" == strCmd)
            {
                printf("exit \n");
                bRun = FALSE;
            }
            else if ("r" == strCmd || "reboot" == strCmd)
            {
                RebootCopmuter();
            }
            else if ("t" == strCmd || "getstate" == strCmd)
            {
                string sComputerName;
                string sIP;
                int   nMemSize;
                int nErrorCode;
                vector<TASKINFO> taskInfos;
                getState(sComputerName, sIP, nMemSize, nErrorCode, taskInfos);
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

            }
            else
            {
                printf("unkown command:%s \n", strCmd.c_str());
                usage();
               
            }
        }
        else if (3 == vCommands.size())
        {

			if ("runtask" == strCmd)
			{
				string strTaskID = vCommands.at(1);
				string strInputFile = vCommands.at(2);
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

				printf(" task ID is:%s\n", strTaskID.c_str());
				printf(" input File  is:%s\n", strInputFile.c_str());

				toSolve(strTaskID, strInputFile);
				strTaskID = "";
				strInputFile = "";
			}
            else if ("upload" == strCmd)
            {
                string strSourceResolvedResultedFile = vCommands.at(1);
                string strDestFileUploaded = vCommands.at(2);

                if (strSourceResolvedResultedFile.empty())
                {
                    printf(" error-- source file name is  empty\n");
                    usage();
                }
                if (strDestFileUploaded.empty())
                {
                    usage();
					printf(" error-- dest File is empty\n");
				}

				printf(" upload source file is:%s\n", strSourceResolvedResultedFile.c_str());
				printf("  upload dest filename  is:%s\n", strDestFileUploaded.c_str());

				upLoadResult(strSourceResolvedResultedFile, strDestFileUploaded);


            }
            else {
                printf("unkown command:%s \n", strCmd.c_str());
                usage();
            }
        }
        else
            usage();

  
    }



    g_pipeMgr[0].Stop();
    g_pipeMgr[1].Stop();

    g_netClient = nullptr;

    ::WSACleanup();
}

