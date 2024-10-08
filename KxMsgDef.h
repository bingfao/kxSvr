#pragma once
#include <cstring>
#include <vector>

#ifndef KX_MSG_COMMON_DEF_H_
#define KX_MSG_COMMON_DEF_H_

constexpr int MAX_LENGTH = 1024;
constexpr int HEAD_TOTAL_LEN = 32;
constexpr int cst_Resp_MsgType = 1;
constexpr int cst_Client_TimeOut_Sec = 500;

constexpr unsigned int cst_nResp_Code_OK = 0;
constexpr unsigned int cst_nResp_Code_RSETSVR = 2;
constexpr unsigned int cst_nResp_Code_DEVID_ERR = 3;

constexpr int MSG_DEV_REGISTER = 1001;
constexpr int MSG_DEV_STATUS = 1002;
constexpr int MSG_DEVCTRL_OPENLOCK = 2001;
constexpr int MSG_APP_DEVCTRL_OPENLOCK = 4001;

#pragma pack(1)

struct KxMsgHeader_Base
{
	unsigned short nMsgId;
	unsigned char nTypeFlag; // 0 Send, 1: Resp
	unsigned short nSeqNum;
	unsigned int nMsgBodyLen;
	unsigned char nCryptFlag;
	unsigned char nReserve[3];
	unsigned short nCrc16;
};

class KxMsgRespHeader : public KxMsgHeader_Base
{
public:
	unsigned int nRespCode;

	KxMsgRespHeader()
		: KxMsgHeader_Base()
	{
		nTypeFlag = cst_Resp_MsgType;
	}
};

class KxMsgHeader : public KxMsgHeader_Base
{
public:
	unsigned int nDevId;
	unsigned int nSessionId; // 由Svr 分配的sessionId

	KxMsgHeader()
		: KxMsgHeader_Base()
	{
		nTypeFlag = 0;
	}
};

struct KxDevRegPacketBody
{
    unsigned short tmYear;
    unsigned char tmMonth;
    unsigned char tmDay;
    unsigned char tmHour;
    unsigned char tmMin;
    unsigned char tmSec;
    unsigned int nDevHwVersion;
    unsigned int nDevSoftVersion;
    unsigned int nMotorCtrlHWVer;
    unsigned int mMotorCtrlSoftVer;
};

struct KxMiniBatteryStatus
{
	//
};

struct KxDevStatusPacketBody_Base
{
	unsigned char nDevType;
	double lngPox;
	double latPos;
	unsigned int nStatus;
	unsigned char szBatteryId[6];
	unsigned char nSocPercent;
	unsigned short nVoltage;
	short nTemperature;
	unsigned char nSeriesCount;
};

struct KxAppDevCtrlOpenLockPacketBody
{
	unsigned int   nDevId;
	unsigned short nAlowTime;
	unsigned char  nLowestSocP;
	unsigned int   nFarthestDist;
};

struct KxDevRegRespPacketBody
{
    unsigned int nDevSessionId;
};

#pragma pack()

#endif