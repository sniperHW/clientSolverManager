
#include <windows.h>

#pragma once


typedef enum _PEOCESS_STATE
{
    STATE_PROCESS_START = 1,
    STATE_PROCESS_READY = 2,
    STATE_PROCESS_RUNING = 3,
    STATE_PROCESS_STOPPED = 4
}STATE_PROCESS;

#define NANE_EVENT_READY_1 "Global\\TexasEventReady1"
#define NANE_EVENT_READY_2 "Global\\TexasEventReady2"


#define NANE_EVENT_RUN_1 "Global\\TexasEventRun1"
#define NANE_EVENT_RUN_1=2 "Global\\TexasEventRun2"

