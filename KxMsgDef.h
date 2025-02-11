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
const unsigned int cst_nResp_Code_PARA_ERR = 6;

const int MSG_DEV_REGISTER = 1001;
const int MSG_DEV_STATUS = 1002;
const int MSG_DEV_USED_TRAFFIC = 1004;
const int MSG_DEV_FILE_RECV_OK = 1020;
const int MSG_DEV_GET_FILE_DATA = 1022;

const int MSG_DEVCTRL_OPENLOCK = 2001;
const int MSG_DEVCTRL_LOCKDEV = 2002;
const int MSG_DEVCTRL_DEVGUARD = 2003;
const int MSG_DEVCTRL_OPENELECLOCK = 2004;
const int MSG_DEVCTRL_LIGHT = 2005;
const int MSG_DEVCTRL_FILEDELIVER_HEADER = 2020;
const int MSG_DEVCTRL_FILEDELIVER_DATA = 2021;
const int MSG_DEVCTRL_FILETOUPDATE_NOTIFY = 2022;

const int MSG_WEBSVR_REGISTER = 9001;
const int MSG_WEBSVR_HEARTBEAT = 9002;

const int MSG_APP_DEVCTRL_OPENLOCK = 4001;
const int MSG_APP_DEVCTRL_LOCKDEV = 4002;
const int MSG_APP_DEVCTRL_DEVGUARD = 4003;
const int MSG_APP_DEVCTRL_OPENELECLOCK = 4004;
const int MSG_APP_DEVCTRL_LIGHT = 4005;
const int MSG_APPTEST_DEVCTRL_FILEDELIVER = 4020;
const int MSG_APPTEST_DEVCTRL_SOCKETDATA_LOG = 4040;

const unsigned int AES_IV_BLOCK_SIZE = 16;
const unsigned int FILE_DATA_BASE_LEN = 256;
const unsigned int FILE_DATA_HEADER_ALLOW_LEN = 4096;
const unsigned int cst_FILE_DATA_PACKET_ALLOW_LEN = 20480;

#pragma pack(1)

struct KxMsgHeader_Base
{
	KxMsgHeader_Base()
		: nMsgId(0), nTypeFlag(0), nSeqNum(0), nMsgBodyLen(0), nReserve{0}, nCryptFlag(0), nCrc16(0)
	{
	}
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
		: KxMsgHeader_Base(), nRespCode(0)
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
		: KxMsgHeader_Base(), nDevId(0), nSessionId(0)
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
	unsigned int mileage;
	bool bDriving;
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

struct KxDevUsedTrafficPacketBody
{
	unsigned char nDevType;
	unsigned char nProtocolFlag;
	unsigned int nUsedTraffic;
};

struct KxAppDevCtrlOpenLock_OrMsg
{
	unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nUsrId;
	unsigned short nAlowTime;
	unsigned char nLowestSocP;
	unsigned int nFarthestDist;
};

struct KxAppDevCtrlLockDev_OrMsg
{
	unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nUsrId;
	unsigned char nVoiceIndex;
};

struct KxAppDevCtrlDevGuard_OrMsg
{
	unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nUsrId;
	unsigned char MotorPowerFlag;
	unsigned char nMaxSpeed;
	unsigned char nVoiceIndex;
};

struct KxAppDevCtrlElecLock_OrMsg
{
	unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nUsrId;
	unsigned char lockFlag;
	unsigned char nVoiceIndex;
};

struct KxAppDevCtrlFileDeliver_Base
{
    unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nSysUsrId;
	unsigned char FileType;
	char szFileName[32];
	unsigned int nFileLen;
	unsigned char fileMd5[16];
	unsigned char szFileData[FILE_DATA_BASE_LEN];
};

struct KxAppDevCtrl_log_SocketData
{
    unsigned int nDevId;
	unsigned char devtype;
	std::time_t svrTime;
	int nSysUsrId;
	unsigned char logSendFlag;
	unsigned char logRecvFlag;
};

struct KxDevCtrlOpenLock_OrMsg
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned short nAlowTime;
	unsigned char nLowestSocP;
	unsigned int nFarthestDist;
};

struct KxDevCtrlLockDev_OrMsg
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned char nVoiceIndex;
};

struct KxDevCtrlDevGuard_OrMsg
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned char MotorPowerFlag;
	unsigned char nMaxSpeed;
	unsigned char nVoiceIndex;
};

struct KxDevCtrlElecLock_OrMsg
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned char lockFlag;
	unsigned char nVoiceIndex;
};

struct KxDevCtrlFileDeliverHeader_OrMsg_Base
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned char FileType;
	char szFileName[32];
	unsigned int nFileLen;
	unsigned char fileMd5[16];
	unsigned char fileData[FILE_DATA_BASE_LEN];
};

struct KxDevFileRecvOK_Msg
{
	unsigned short tmYear;
	unsigned char tmMonth;
	unsigned char tmDay;
	unsigned char tmHour;
	unsigned char tmMin;
	unsigned char tmSec;
	
	unsigned char devtype;
	unsigned char recvFlag;
	unsigned char FileType;
	char szFileName[32];
	unsigned int nFileLen;
	unsigned char fileMd5[16];
};

struct KxDevGet_FileData_Msg
{
	unsigned char nDevType;
	unsigned char FileType;
	char szFileName[32];
	unsigned char fileURL_KEY[16];
	unsigned int nFileDataPos;
	unsigned short nDataLen;
};

struct KxDev_FileData_Msg_Base
{
	unsigned int nFileDataPos;
	unsigned short nDataLen;
	unsigned char fileData[3];
};

struct KxDevFileUpdateNotify_OrMsg
{
	std::time_t svrTime;
	unsigned int nSessionId;
	unsigned char FileType;
	char szFileName[32];
	unsigned int nFileLen;
	unsigned char fileMd5[16];
	unsigned char fileURL_KEY[16];
};

struct KxDevCtrlFileDeliverFileData_Base
{
	unsigned int nSessionId;
	unsigned char FileType;
	char szFileName[32];
	unsigned int nFileDataPos;
	unsigned short nDataLen;
	unsigned char fileData[3];
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
	std::time_t curTime;
};

struct KxWebSvrHeartBeat
{
	std::time_t curTime;
	char szHost[32];
};

struct KxWebSvrHeartBeatResp
{
	unsigned int ntotalDevCount;
	std::time_t svrStartTime;
};

#pragma pack()

#endif