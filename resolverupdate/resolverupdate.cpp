// resolverupdate.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdlib>
#include<direct.h>
#include <tchar.h>
#include <WinNetWk.h>
#include <stdio.h>

#pragma comment(lib, "Mpr.lib")

#define  VOL_SHARE_UPDATE "X:"

#define  VOL_SHARE_UPLOAD "Z:"

//system("net use \\\\192.168.1.100\\ck\\a b /user:a");

int AccessShareFolder(const char* szUserName,const char* szPasswd, const char* lpRemotePath, const char* szShareVolume)
{
    int iRet = -1;
    NETRESOURCE net_Resource;
   // net use K : \\192.168.90.200\目录 密码 / user:用户名
    char sShareCommand[1024] = { 0 };
   // sprintf_s(sShareCommand, 1024, "net use x: %s %s /user:%s /PERSISTENT:YES", lpRemotePath, szPasswd, szUserName);
    sprintf_s(sShareCommand, 1024, "net use %s %s %s /user:%s ", szShareVolume, lpRemotePath, szPasswd, szUserName);
    system(sShareCommand);
    Sleep(1000);
    net_Resource.dwDisplayType = RESOURCEDISPLAYTYPE_DIRECTORY;
    net_Resource.dwScope = RESOURCE_CONNECTED;
    net_Resource.dwType = RESOURCETYPE_ANY;// RESOURCETYPE_DISK | RESOURCETYPE_ANY;// RESOURCETYPE_ANY;
    net_Resource.dwUsage = 0;
    char szComment[] = "update";
    net_Resource.lpComment = &szComment[0];

    net_Resource.lpLocalName = const_cast<char*>(szShareVolume);  //映射成本地驱动器z:
    net_Resource.lpProvider = NULL;
    net_Resource.lpRemoteName = const_cast<char*>(lpRemotePath);// TEXT("\\\\192.168.0.2\\管理部"); // \\servername\共享资源名
    DWORD dwFlags = CONNECT_UPDATE_PROFILE;// | CONNECT_INTERACTIVE | CONNECT_COMMANDLINE | CONNECT_CMD_SAVECRED;// CONNECT_UPDATE_PROFILE;
    DWORD dw = WNetAddConnection3A(NULL,&net_Resource, szPasswd, szUserName, dwFlags);
    switch (dw)
    {
    case ERROR_SUCCESS:
       // ShellExecute(NULL, TEXT("open"), szShareVolume, NULL, NULL, SW_SHOWNORMAL);
        printf(TEXT("共享目录访问成功！"));
        iRet = 0;
        break;
    case ERROR_ACCESS_DENIED:
        printf(TEXT("没有权访问！"));
        iRet = -2;
        break;
    case ERROR_ALREADY_ASSIGNED:
       // ShellExecute(NULL, TEXT("open"), szShareVolume, NULL, NULL, SW_SHOWNORMAL);
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


using namespace std;
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

bool dirExists(const std::string& dir)
{
   
    DWORD attribs = ::GetFileAttributesA(dir.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    return (attribs & FILE_ATTRIBUTE_DIRECTORY);
}

int InitUploadSharePath()
{
    int iRet = -1;
    char cBuf[256] = { 0 };
    string sCurPath = GetCurrentPath();
   // string sConfigFile = sCurPath + "resolvermanager.ini";
    string sConfigFile = sCurPath + "updateConfig.ini";
    // share path
    DWORD dwRet = GetPrivateProfileStringA("uploadserver", "sharePath", "",
        cBuf, 256, sConfigFile.c_str());
    if (dwRet < 2)
    {
        ::printf("get update config failed:%d\n", GetLastError());
        return -1;
    }
    string sServerSharePath = cBuf;

    //username
    ZeroMemory(cBuf, sizeof(cBuf));
    dwRet = GetPrivateProfileStringA("uploadserver", "username", "",
        cBuf, 256, sConfigFile.c_str());
    if (0 == dwRet)
    {
        ::printf("get username failed:%d\n", GetLastError());
        return -3;
    }
    string sNetUsername = cBuf;

    //password
    ZeroMemory(cBuf, sizeof(cBuf));
    dwRet = GetPrivateProfileStringA("uploadserver", "password", "",
        cBuf, 256, sConfigFile.c_str());
    if (0 == dwRet)
    {
        ::printf("get username failed:%d\n", GetLastError());
        return -3;
    }
    string sPassword = cBuf;

    //确认网络共享是否可以访问
    iRet = AccessShareFolder(sNetUsername.c_str(), sPassword.c_str(), sServerSharePath.c_str(), VOL_SHARE_UPLOAD);
    if (0 != iRet)
    {
        ::printf("acess share remote path failed:%d--%d\n", iRet, GetLastError());
        return -4;
    }
    return 0;
}


int InitUpdateSharePath()
{
    int iRet = 0;
    char cBuf[256] = { 0 };
    string sCurPath = GetCurrentPath();
    string sConfigFile = sCurPath + "updateConfig.ini";
    do
    {
        // share path
        DWORD dwRet = GetPrivateProfileStringA("updateserver", "sharePath", "",
            cBuf, 256, sConfigFile.c_str());
        if (dwRet < 2)
        {
            printf("get update config failed:%d\n", GetLastError());
            iRet = -1;
            break;
        }
        string sServerSharePath = cBuf;

        //username
        ZeroMemory(cBuf, sizeof(cBuf));
        dwRet = GetPrivateProfileStringA("updateserver", "username", "",
            cBuf, 256, sConfigFile.c_str());
        if (0 == dwRet)
        {
            printf("get username failed:%d\n", GetLastError());
            iRet = -2;
            break;
        }
        string sNetUsername = cBuf;

        //password
        ZeroMemory(cBuf, sizeof(cBuf));
        dwRet = GetPrivateProfileStringA("updateserver", "password", "",
            cBuf, 256, sConfigFile.c_str());
        if (0 == dwRet)
        {
            printf("get username failed:%d\n", GetLastError());
            iRet = -3;
            break;
        }
        string sPassword = cBuf;

        //确认网络共享是否可以访问
        iRet = AccessShareFolder(sNetUsername.c_str(), sPassword.c_str(), sServerSharePath.c_str(),VOL_SHARE_UPDATE);
        if (0 != iRet)
        {
            printf("acess share remote path failed:%d--%d\n", iRet, GetLastError());
            iRet = -4;
            break;
        }
    } while (0);
    return iRet;
}
BOOL isRunasAdministrator()
{
    HANDLE hToken;
    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize;
    BOOL bRet = FALSE;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize);

    bool bUAC_Enabled = false;

    switch (elevationType) {
    case TokenElevationTypeDefault:

        printf(TEXT("\nTokenElevationTypeDefault - User is not using a split token.\n"));
        break;
    case TokenElevationTypeFull:

        printf(TEXT("\nTokenElevationTypeFull - User has a split token, and the process is running elevated.\n"));
        bRet = TRUE;
        break;
    case TokenElevationTypeLimited:

        printf(TEXT("\nTokenElevationTypeLimited - User has a split token, but the process is not running elevated.\n"));
        break;
    }

    if (hToken) {
        CloseHandle(hToken);
    }
    return bRet;
}

int main(int argc,char** argv)
{
    int iRet = -1;
    char cBuf[256] = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    char sCommand[1024] = { 0 };
    BOOL bRet = FALSE;

	string sCurPath = GetCurrentPath();

	//iRet = InitUploadSharePath();
	//if (0 != iRet)
	//{
	//	printf(" InitUploadSharePath return error:%d \n", iRet);
	//}
     do
    {
        iRet = InitUpdateSharePath();
        if (0 != iRet)
        {
            printf(" InitUpdateSharePath return error:%d \n", iRet);
            break;
        }

        //string  sServerVersionFile = sServerSharePath + "\\version.ini";
        string  sServerVersionFile = VOL_SHARE_UPDATE;
        sServerVersionFile  += "\\version.ini";
        string  sLocalVersinFile = sCurPath + "version.ini";
        ZeroMemory(cBuf, sizeof(cBuf));
        DWORD dwRet = GetPrivateProfileStringA("version", "fileversion", "",
            cBuf, 256, sServerVersionFile.c_str());
        if (0 == dwRet)
        {
            printf("get server Version config failed:%d\n", GetLastError());
            iRet = -5;
            break;
        }
        string sServerVersion = cBuf;

        string sLocalVersion;
        ZeroMemory(cBuf, sizeof(cBuf));
        dwRet = GetPrivateProfileStringA("version", "fileversion", "",
            cBuf, 256, sLocalVersinFile.c_str());
        if (0 == dwRet)
        {
            printf("get Local Version config failed:%d\n", GetLastError());
            sLocalVersion = "";
        }
        else
        {
            sLocalVersion = cBuf;
        }
        if (!sLocalVersion.empty() && sLocalVersion == sServerVersion)
        {
            printf(" no update:%s\n", sServerVersion.c_str());
            iRet = 1;
            break;
        }
		string sRemoteSDir;
        sRemoteSDir = VOL_SHARE_UPDATE;
        sRemoteSDir  += "\\";

        si.cb = sizeof(STARTUPINFO);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = /*SW_MINIMIZE*/ SW_HIDE; //*/ SW_SHOW;
	   sprintf_s(sCommand, 1024, "xcopy /E /H /C /Y %s  %s", sRemoteSDir.c_str(), sCurPath.c_str());
		bRet = CreateProcessA(
			NULL,
			&sCommand[0],
			NULL, NULL, TRUE,
			NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,// CREATE_NO_WINDOW,
			NULL, NULL, &si, &pi);
		if (FALSE == bRet)
		{
			printf(" CreateProcessA failed error:%d-:%s\n", GetLastError(), sCommand);
			iRet = - 101;
		}
		else
		{
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}    
    }while (0);



    return 0;

    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = /*SW_MINIMIZE SW_HIDE;*/ SW_SHOW;
    ZeroMemory(sCommand, sizeof(sCommand));
    ZeroMemory(&pi,sizeof(pi));

    sprintf_s(sCommand, 1024, "%s%s", sCurPath.c_str(),"Resolvergr.exe");
    bRet = CreateProcessA(
        NULL,
        &sCommand[0],
        NULL, NULL, TRUE,
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,// CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);
    if (FALSE == bRet)
    {
        printf(" create failed error:%d--:%s\n", GetLastError(), sCommand);
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    // Initialize the structure.

    //SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };

    //// Ask for privileges elevation.

    //sei.lpVerb = TEXT("runas");

    //// Create a Command Prompt fromwhich you will be able to start

    //// other elevated applications.

    //sei.lpFile = sCommand;

    //sei.lpParameters =NULL;

    //// Don't forget this parameter; otherwise, the window will be hidden.

    //sei.nShow = SW_SHOWNORMAL;

    //ShellExecuteEx(&sei);
    return 0;
}
