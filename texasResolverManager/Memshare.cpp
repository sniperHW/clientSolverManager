// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <math.h>
#include <memoryapi.h>
#include "Card.h"
#include "memshare.h"

using namespace std;

#pragma pack(4)
typedef struct {
    uint64_t  lCardLong;
    int       rank;
}D5CompareItem,*LPD5CompareItem;
#pragma pack()

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

BOOL GetMemAvailable(int& dwMemAvail)
{
    _MEMORYSTATUSEX  msEx;
    msEx.dwLength = sizeof(msEx);
    BOOL  bRet = ::GlobalMemoryStatusEx(&msEx);
    if (bRet)
    {
        dwMemAvail = (int)(msEx.ullAvailPhys / (1024 * 1024));
    }
    return bRet;
}

HANDLE g_hMemFile = INVALID_HANDLE_VALUE;
LPD5CompareItem g_pCompareItemHeader = NULL;

int InitMemshare()
{
    int iRet = 0;
    if (INVALID_HANDLE_VALUE != g_hMemFile)
    {
        CloseMemshare();
    }
    string strDic = GetCurrentPath();
    strDic += "resources\\compairer\\card5_dic_sorted.txt";
    std::ifstream infile;
    std::string sLine;
    infile.open(strDic.c_str(), std::ios::in);
    if (!infile.is_open())
    {
        ::printf(" open memshare dictionary file failed:%d\n", GetLastError());
        return -11;
    }
    DWORD dwTime = GetTickCount();
//内存映射文件
  //  FILE_MAP_ALL_ACCESS
    do {
        //说明，内存大小要大于(行数+1)*12
         g_hMemFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,PAGE_READWRITE, 0, 30 * 1024 * 1024, "Global\\TexasResolverCompaire");
        if (g_hMemFile == NULL || INVALID_HANDLE_VALUE == g_hMemFile) {
            printf("InitMemshare Can't create a file mapping. err = %d", GetLastError());
            iRet = -1;
            break;
        }

        g_pCompareItemHeader = (LPD5CompareItem)MapViewOfFile(g_hMemFile, FILE_MAP_WRITE, 0, 0, 0);
        if (g_pCompareItemHeader == NULL) {
            printf("InitMemshare cant get pointer to mapping file. err = %d", GetLastError());
            iRet = -2;
            break;
        }

        LPD5CompareItem pCurItem = g_pCompareItemHeader + 1;
        int iCompareItemCount = 0;
        while (std::getline(infile, sLine)) {

            //std::cout << sLine << std::endl;

            vector<string> linesp = string_split(sLine, ',');
            if (linesp.size() != 2) {
               printf("InitMemshare -- linesp not correct: %s \n",sLine.c_str() );
                throw runtime_error("read line return not two element  - 1");
            }
            string cards_str = linesp[0];
            pCurItem->rank = stoi(linesp[1]);
            vector<string> cards = string_split(cards_str, '-');

            if (cards.size() != 5)
            {
                printf("InitMemshare --cards not correct ：%s --length(cardsize):%zd  \n", cards_str.c_str(), cards.size());
                throw runtime_error("cards not length correct ");
            }
            pCurItem->lCardLong = Card::boardCards2long(cards);
            pCurItem++;
            iCompareItemCount++;
        }
        printf(" meshare total items: %d \n ", iCompareItemCount);
        g_pCompareItemHeader->lCardLong = 0x12345678;
        g_pCompareItemHeader->rank = iCompareItemCount;
        iRet = 0;

    } while (false);

     dwTime = GetTickCount() - dwTime;
     dwTime /= 1000;
     printf(" esharte used seconds: %d \n", dwTime);
     return iRet;
}

void CloseMemshare()
{
    if (NULL != g_pCompareItemHeader)
    {
        UnmapViewOfFile(g_pCompareItemHeader);
        g_pCompareItemHeader = NULL;
    }
    if (g_hMemFile != NULL && INVALID_HANDLE_VALUE != g_hMemFile)
    {
        CloseHandle(g_hMemFile);
        g_hMemFile = INVALID_HANDLE_VALUE;
    }
}

