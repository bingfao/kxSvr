#pragma once


#ifndef KX_MSG_COMMON_DEF_H_
#define KX_MSG_COMMON_DEF_H_

const int MAX_LENGTH = 1024;
const int HEAD_TOTAL_LEN = 32;
const int cst_Resp_MsgType = 1;
const int cst_Client_TimeOut_Sec = 500;
const int cst_Svr_Wait_DevMsgResp_Sec = 30;

const unsigned int cst_nResp_Code_OK = 0;
const unsigned int cst_nResp_Code_RSETSVR = 2;
const unsigned int cst_nResp_Code_DEV_OFFLINE = 3;
const unsigned int cst_nResp_Code_DEVID_ERR = 4;
const unsigned int cst_nResp_Code_SEND_DEV_ERR = 5;

const int MSG_DEV_REGISTER = 1001;
const int MSG_DEV_STATUS = 1002;
const int MSG_DEVCTRL_OPENLOCK = 2001;

const int MSG_WEBSVR_REGISTER = 9001;
const int MSG_APP_DEVCTRL_OPENLOCK = 4001;

const unsigned int AES_IV_BLOCK_SIZE = 16;

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

class KxMsgReqHeader : public KxMsgHeader_Base
{
public:
	unsigned int nDevId;
	unsigned int nSessionId; // 由Svr 分配的sessionId

	KxMsgReqHeader()
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
	unsigned int nDashBoardHWVer;
	unsigned int nDashBoardSoftVer;
};



struct KxDev_Status_
{
	unsigned char lockStatus;
	unsigned short lightStatus;
	unsigned char sensorStatus;
	unsigned char brakeStatus;
	unsigned char reserved;
};

struct KxDev_MiniBatteryStatus_
{
	unsigned char socPercent;
	unsigned short voltage;
	unsigned short temp;
};

struct KxDev_BatteryStatus_
{
	unsigned char socPercent;
	unsigned short voltage;
	unsigned short temp;
	unsigned char currentFlag;
	unsigned short current;
};

struct KxDev_BatterySerieData_
{
	unsigned short voltage;
	unsigned short temp;
};

struct KxDevStatusPacketBody_Base
{
	unsigned char nDevType;
	unsigned char nProtocolFlag;
	double lngPos;
	double latPos;
	bool bDriving;
	unsigned int mileage;   
	short speed;
	KxDev_Status_ Status;
	bool bMiniBatExist;
	char szMiniBatteryId[30];
	KxDev_MiniBatteryStatus_ miniBatteryStatus;
	bool batteryExist;
	bool chargeFlag;
	char szBatteryId[32];
	KxDev_BatteryStatus_ batteryStatus;
	unsigned char seriesCount;
	KxDev_BatterySerieData_ seriesData;
};

struct KxAppDevCtrlOpenLock_OriginMsg
{
	unsigned int nDevId;
	unsigned char devtype;
	std::time_t  svrTime;
	int  nUsrId;
	unsigned short nAlowTime;
	unsigned char nLowestSocP;
	unsigned int nFarthestDist;
};

struct KxDevRegRespPacketBody
{
	unsigned int nDevSessionId;
	unsigned char szIV[AES_IV_BLOCK_SIZE];
};

struct KxWebSvrRegRespPacketBody_OriginMsg
{
	unsigned int nSessionId;
	unsigned char szIV[AES_IV_BLOCK_SIZE];
	std::time_t  curTime;
};

struct KxWebSvrHeartBeat {
	std::time_t  curTime;
	char szHost[32];
};

#pragma pack()

#endif