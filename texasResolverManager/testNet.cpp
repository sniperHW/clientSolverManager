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

//namespace fs = std::filesystem;

#include "json.hpp"
#include "net.h"
#include  "rpipe.h"
#include  "memshare.h"
#include <filesystem>

#pragma comment(lib,"ws2_32.lib")

using namespace std;
using json = nlohmann::json;

#define  VOL_SHARE_UPDATE "X:"

#define  VOL_SHARE_UPLOAD "Z:"

typedef struct _TASKINFO
{
    string sCurTaskID;
    int nContinuedSeconds; //单位，毫秒
    int nIterationNum;
    double dExploit;
    BOOL bFinished;

    _TASKINFO()
    {
        sCurTaskID = "";
        nContinuedSeconds = 0;
        nIterationNum = 0;
        dExploit = 0.0;
        bFinished = FALSE;
    }
    _TASKINFO(const string& sCurTaskID, int nContinuedSeconds, int nIterationNum, double dExploit) :
        sCurTaskID(sCurTaskID), nContinuedSeconds(nContinuedSeconds), nIterationNum(nIterationNum), dExploit(dExploit) {}


}TASKINFO, * LPTASKINFO;


#define NUM_PROCESS_1  1
#define NUM_PROCESS_2  2

#define ERROR_INITSHAREPATH_FAILED  1002
#define ERROR_INITMEMSHARE_FAILED  1003

DWORD g_dwResolverNum = 1;
int g_nErrorCode = 0;


string g_sComputerName;
string g_sLocalIP;
DWORD g_dwMemSize = 0;


void GetSytemInfo()
{
    char Buf[256] = { 0 };
    ZeroMemory(Buf, sizeof(Buf));
    DWORD dwSize = sizeof(Buf);
    BOOL bRet = GetComputerNameA(Buf, &dwSize);
    if (bRet)
    {
        ::printf(" computerName:%s \n", Buf);
        g_sComputerName = Buf;
    }
    _MEMORYSTATUSEX  msEx;
    msEx.dwLength = sizeof(msEx);
    bRet = ::GlobalMemoryStatusEx(&msEx);
    if (bRet)
    {
        g_dwMemSize = (DWORD)(msEx.ullTotalPhys / (1024 * 1024));
        ::printf("mem size:%d \n", g_dwMemSize);
    }



    //获得主机名称
    char szHost[256] = { 0 };
    ::gethostname(szHost, 256);
    ::printf("主机名=%s", szHost);
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
        strIP.append("|");
        g_sLocalIP.append(strIP);
    }
    ::printf(" local ip:%s \n", g_sLocalIP.c_str());
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
    //std::string resultPath;
    taskState   state;
    int         nContinuedSeconds; //单位，毫秒
    int         nIterationNum;
    double      dExploit;

    task() :nContinuedSeconds(0), nIterationNum(0), dExploit(0) {

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

std::map<std::string, std::shared_ptr<task>> taskMap;
std::mutex taskMapMtx;

net::Buffer::Ptr makeHeartBeatPacket(const std::vector<TASKINFO>& tasks) {
    json j;
    j["WorkerID"] = g_sLocalIP;
    j["Memory"] = g_dwMemSize / 1024;
    auto Tasks = json::array();

    for (auto it = tasks.begin(); it != tasks.end(); it++) {
        json t;
        t["TaskID"] = (*it).sCurTaskID;
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


void commitTaskRoutine(const std::shared_ptr<task>& task) {
    json j;
    j["TaskID"] = task->taskID;
    j["Result"] = "hello";

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
            g_netClient->Send(makeHeartBeatPacket(tasks));
            return;
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
    auto t = std::thread(commitTaskRoutine, task);
    t.detach();
}


void onPacket(const net::Buffer::Ptr& packet) {
    auto rawBuf = packet->BuffPtr();
    auto cmd = ::ntohs(*(uint16_t*)rawBuf);
    auto jsonStr = std::string(&rawBuf[2], packet->Len() - 2);
    auto msg = json::parse(jsonStr);

    switch (cmd) {
    case 2: {//CmdDispatchJob
        auto taskID = msg["TaskID"].get<std::string>();
        auto CfgPath = msg["TaskID"].get<std::string>();
        taskMapMtx.lock();
        auto t = taskMap[msg["TaskID"].get<std::string>()];
        taskMapMtx.unlock();
        if (t != nullptr) {
            return;
        }

        std::ofstream ofs;
        ofs.open(taskID, std::ios::out);
        ofs << msg["Cfg"].get<std::string>();
        ofs.close();

        t = std::shared_ptr<task>(new task());
        t->taskID = taskID;
        t->state = taskRunning;


        std::vector<TASKINFO> tasks;
        taskMapMtx.lock();
        taskMap[taskID] = t;
        for (auto it = taskMap.begin(); it != taskMap.end(); it++) {
            tasks.push_back(_TASKINFO(it->second->taskID, it->second->nContinuedSeconds, it->second->nIterationNum, it->second->dExploit));
        }
        taskMapMtx.unlock();
        g_netClient->Send(makeHeartBeatPacket(tasks));

        auto tt = std::thread([taskID]() {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            TaskFinish(taskID);
            });
        tt.detach();


    }
          break;
    case 4://CmdAcceptJobResult = uint16(4)
    case 5: {//CmdCancelJob       = uint16(5)


        auto taskID = msg["TaskID"].get<std::string>();

        //删除本地文件
        filesystem::remove(taskID); //cfg文件
        std::filesystem::remove(taskID + ".json");//结果文件

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
        string sComputerName = "";
        string sIP = "";
        vector<TASKINFO> tasks;
        taskMapMtx.lock();
        for (auto it = taskMap.begin(); it != taskMap.end(); it++) {
            tasks.push_back(_TASKINFO(it->second->taskID, it->second->nContinuedSeconds, it->second->nIterationNum, it->second->dExploit));
        }

        taskMapMtx.unlock();

        g_netClient->Send(makeHeartBeatPacket(tasks));

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

int  InitTaskShedule()
{
    char serverIp[64] = { 0 };


    std::string sPath = GetCurrentPath();
    string sConfigFile = sPath + "resolvermanager.ini";

    DWORD dwRet = GetPrivateProfileStringA("taskserver", "IP", "127.0.0.1",
        serverIp, 64, sConfigFile.c_str());
    if (dwRet < 7)
    {
        ::printf(" Get taskserver IP from  config file  failed:%d\n", GetLastError());
        return -1;
    }

    u_short serverPort = (u_short)GetPrivateProfileIntA("taskserver", "Port",
        18889, sConfigFile.c_str());

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
    auto t = std::thread(heartbeatRoutine);
    t.detach();

    return 0;
}
int main(int argc, char** argv)
{

    int iRet = -1;


    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    //初始化socket环境
    if (::WSAStartup(sockVersion, &wsaData) != 0)
    {
        return -1;
    }

    GetSytemInfo();

    std::string sPath = GetCurrentPath();
    ::printf("current path is :%s \n", sPath.c_str());

    string strInput;

    if (0 != InitTaskShedule())
    {
        ::printf(" InitTaskShedule failed \n");
        g_netClient = nullptr;

        ::WSACleanup();
        return -11;
    }

    getline(cin, strInput);
    g_netClient = nullptr;

    ::WSACleanup();
}

