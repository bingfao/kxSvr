#include "KxLogicSys.hpp"
#include "KxMsgNode.hpp"
#include "KxSession.hpp"
#include "KxLogger.hpp"
#include "aeshelper.hpp"
#include <cstring>
#include <chrono>
#include <openssl/evp.h>

#ifdef USING_PQ_DB_
#include <pqxx/pqxx>
#endif

using namespace std::chrono_literals;

const char cst_szHost[] = "kingxun.site";

const unsigned char default_aes_key[] = {0x51, 0x5D, 0x3D, 0x22, 0x97, 0x47, 0xC8, 0xFD, 0x9F, 0x30, 0x41, 0xD0, 0x8C, 0x0A, 0xE9, 0x10};
const unsigned char default_aes_iv[] = {0x13, 0xF1, 0xDA, 0xC8, 0x8B, 0xB6, 0xE2, 0xCD, 0x9B, 0xEA, 0xE0, 0x63, 0x8F, 0x3F, 0x53, 0xAB};

void Kx_MD5(unsigned char *szbuf, int nbufLen, unsigned char *md5_digest,
			int &ndigestLen)
{
	unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
	if (ndigestLen >= md5_digest_len)
	{
		// MD5_Init
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
		// MD5_Update
		EVP_DigestUpdate(mdctx, szbuf, nbufLen);
		// MD5_Final
		EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
		ndigestLen = (int)md5_digest_len;
		EVP_MD_CTX_free(mdctx);
	}
}

KxBusinessLogicMgr::KxBusinessLogicMgr() : _b_stop(false)
{
	RegisterCallBacks();
	m_worker_thread = std::thread(&KxBusinessLogicMgr::DealMsg, this);
}

KxBusinessLogicMgr::~KxBusinessLogicMgr()
{
	_b_stop = true;
	m_cond_consume.notify_one();
	m_worker_thread.join();
}

void KxBusinessLogicMgr::PostMsgToQue(std::shared_ptr<KxBussinessLogicNode> msg)
{
	std::unique_lock<std::mutex> unique_lk(m_mutex);
	m_recvedMsg_que.push(msg);
	// 由0变为1则发送通知信号
	if (m_recvedMsg_que.size() == 1)
	{
		unique_lk.unlock();
		m_cond_consume.notify_one();
	}
}

void KxBusinessLogicMgr::DealMsg()
{
	for (;;)
	{
		std::unique_lock<std::mutex> unique_lk(m_mutex);
		// 判断队列为空则用条件变量阻塞等待，并释放锁
		while (m_recvedMsg_que.empty() && !_b_stop)
		{
			m_cond_consume.wait(unique_lk);
		}

		// 判断是否为关闭状态，把所有逻辑执行完后则退出循环
		if (_b_stop)
		{
			while (!m_recvedMsg_que.empty())
			{
				dealOneMsg();
			}
			break;
		}
		dealOneMsg();
	}
}

void KxBusinessLogicMgr::dealOneMsg()
{
	auto msg_node = m_recvedMsg_que.front();
	auto msgPacket = msg_node->m_recvedPacket;
	auto msgHeader = msgPacket->getMsgHeader();
	auto msg_id = msgHeader.nMsgId;
	auto nDevId = msgPacket->getDevId();

	// std::cout << "recv_msg id  is " << msg_id;
	std::string strLog = "recv_msg id  is " + std::to_string(msg_id);
	strLog += " seqNum: " + std::to_string(msgHeader.nSeqNum);
	if (msgHeader.nTypeFlag == cst_Resp_MsgType)
		// std::cout << " resp ";
		strLog += " resp ";
	else
		// std::cout << ", devId: " << nDevId;
		strLog += ", devId: " + std::to_string(nDevId);
	// std::cout << std::endl;
	KX_LOG_FUNC_(strLog);
	auto call_back_iter = m_map_FunCallbacks.find(msg_id);
	if (call_back_iter != m_map_FunCallbacks.end())
	{
		call_back_iter->second(msg_node->m_session, *msg_node->m_recvedPacket);
	}

	if (msgHeader.nTypeFlag == cst_Resp_MsgType)
	{
		msg_node->m_session->onMsgResp(msgPacket);
	}
	m_recvedMsg_que.pop();
}

void KxBusinessLogicMgr::RegisterCallBacks()
{
	m_map_FunCallbacks[MSG_DEV_REGISTER] = std::bind(&KxBusinessLogicMgr::DevRegMsgCallBack, this,
													 std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_DEV_STATUS] = std::bind(&KxBusinessLogicMgr::DevStatusMsgCallBack, this,
												   std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_APP_DEVCTRL_OPENLOCK] = std::bind(&KxBusinessLogicMgr::AppCtrlOpenLockMsgCallBack, this,
															 std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_APP_DEVCTRL_LOCKDEV] = std::bind(&KxBusinessLogicMgr::AppCtrlLockDevMsgCallBack, this,
															std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_APP_DEVCTRL_DEVGUARD] = std::bind(&KxBusinessLogicMgr::AppCtrlDevGuardMsgCallBack, this,
															 std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_APP_DEVCTRL_OPENELECLOCK] = std::bind(&KxBusinessLogicMgr::AppCtrlDevElecLockCallBack, this,
																 std::placeholders::_1, std::placeholders::_2);

	m_map_FunCallbacks[MSG_APPTEST_DEVCTRL_FILEDELIVER] = std::bind(&KxBusinessLogicMgr::AppCtrlDevFileDeliverCallBack, this,
																	std::placeholders::_1, std::placeholders::_2);

	m_map_FunCallbacks[MSG_WEBSVR_REGISTER] = std::bind(&KxBusinessLogicMgr::WebSvrRegMsgCallBack, this,
														std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_WEBSVR_HEARTBEAT] = std::bind(&KxBusinessLogicMgr::WebSvrHeartBeatMsgCallBack, this,
														 std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_DEV_USED_TRAFFIC] = std::bind(&KxBusinessLogicMgr::DevUsedTrafficMsgCallBack, this,
														 std::placeholders::_1, std::placeholders::_2);
	m_map_FunCallbacks[MSG_DEV_GET_FILE_DATA] = std::bind(&KxBusinessLogicMgr::DevGetFileDataMsgCallBack, this,
														  std::placeholders::_1, std::placeholders::_2);
}

void KxBusinessLogicMgr::WebSvrHeartBeatMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	char *pHost = (char *)(pMsgBody + 8);
	if (std::strcmp(cst_szHost, pHost) == 0)
	{
		KxMsgHeader_Base msgRespHead_base;
		msgRespHead_base.nMsgId = msgHeader.nMsgId;
		msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
		msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
		const std::time_t t_c = std::time(nullptr);
		KxWebSvrHeartBeatResp respbody;
		msgRespHead_base.nMsgBodyLen = sizeof(respbody);
		respbody.ntotalDevCount = session->getDevCount();
		respbody.svrStartTime = session->getSvrStartTime();
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, (unsigned char *)&respbody, true);
		session->setLastTime(t_c);
	}
}

void KxBusinessLogicMgr::WebSvrRegMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// 解密处理
	unsigned char *originMsgBody = nullptr;
	unsigned int nMsgBufLen = 0;

	session->setAES_Key(default_aes_key);
	session->setAES_Iv(default_aes_iv);
	bool brt = session->checkAESPacketData(pMsgBody, msgHeader.nMsgBodyLen, originMsgBody, nMsgBufLen);
	if (brt && originMsgBody && nMsgBufLen)
	{
		// 把时间和host信息都打印出来
		char *pHost = (char *)(originMsgBody + 8);
		std::stringstream ssout;
		ssout << "origin msg host : " << pHost << std::endl;
		if (std::strcmp(cst_szHost, pHost) == 0)
		{
			KxMsgHeader_Base msgRespHead_base;
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			KxWebSvrRegRespPacketBody_OriginMsg originRespData;
			// unsigned char originRespData[AES_IV_BLOCK_SIZE + 8] = {0};
			const std::time_t t_c = std::time(nullptr);
			Rand_IV_Data(originRespData.szIV);
			// memcpy(originRespData + 16, &t_c, sizeof(std::time_t));
			originRespData.nSessionId = session->GetSessionId();
			originRespData.curTime = t_c;
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *poriginRespData = (unsigned char *)&originRespData;
			brt = session->AES_encrypt(poriginRespData, sizeof(originRespData), msgBody, nBufLen);
			if (brt)
			{
				session->setWebSvr();
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(originRespData);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(poriginRespData, sizeof(originRespData));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgRespHead_base.nMsgBodyLen = nBufLen;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, msgBody, true);
				session->setAES_Iv(originRespData.szIV);
				ssout << "Set New IV Data: " << std::hex;
				for (int i = 0; i < AES_IV_BLOCK_SIZE; ++i)
				{
					ssout << std::setw(2) << std::setfill('0') << (short)poriginRespData[i] << ' ';
				}
				// ssout << std::dec << std::endl;
				KX_LOG_FUNC_(ssout.str());
			}
			session->setLastTime(t_c);
		}
		else
		{
			KX_LOG_FUNC_("invalid WebSvrRegMsg.");
		}
		delete[] originMsgBody;
		originMsgBody = nullptr;
	}
}

void KxBusinessLogicMgr::DevRegMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	// 这里可以做一些逻辑判断处理
	KxMsgHeader_Base msgRespHead_base;
	auto msgHeader = msgPacket.getMsgHeader();
	msgRespHead_base.nMsgId = msgHeader.nMsgId;
	msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
	msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
#ifdef SUPPORT_REDIRECT_SVR_
	static unsigned int nVal = 0;
	++nVal;
	if (nVal % 2 == 0)
	{
		unsigned char szPacket[64] = {0};
		const char *szSvrIp = "127.0.0.1";
		szPacket[0] = strlen(szSvrIp) + 1;
		memcpy(szPacket + 1, szSvrIp, szPacket[0]);
		unsigned short *pPort = (unsigned short *)(szPacket + szPacket[0] + 1);

#ifdef USING_DIFFERENT_PORT
		*pPort = 10086;
#else
		*pPort = 10085;
#endif

		msgRespHead_base.nMsgBodyLen = szPacket[0] + 3;
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		session->SendRespPacket(msgRespHead_base, cst_nResp_Code_RSETSVR, szPacket, true);
	}
	else
#else
	{
		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);
		unsigned char szPacketBody[20] = {0};
		msgRespHead_base.nMsgBodyLen = sizeof(szPacketBody);
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		unsigned int nBodySessionId = session->GetSessionId();
		auto nDevId = msgPacket.getDevId();
		session->updateDevSessionId(nDevId, nBodySessionId);
		session->getDevAESKeyData();
		*(unsigned int *)(szPacketBody) = nBodySessionId;
		memcpy(szPacketBody + 4, session->getAESIvData(), AES_IV_BLOCK_SIZE);
		session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, szPacketBody, true);
	}
#endif
}

void KxBusinessLogicMgr::DevStatusMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	// 这里可以做一些逻辑判断处理
	KxMsgHeader_Base msgRespHead_base;
	auto msgHeader = msgPacket.getMsgHeader();
	msgRespHead_base.nMsgId = msgHeader.nMsgId;
	msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
	msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
	msgRespHead_base.nMsgBodyLen = 0;
	msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
	session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, nullptr, false);
	const std::chrono::time_point<std::chrono::system_clock> tp_now =
		std::chrono::system_clock::now();
	const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
	session->setLastTime(t_c);
#ifdef USING_PQ_DB_
	try
	{
		// pqxx::connection c{"host=localhost port=5432 dbname=kingxun user=postgres password=bingfao"};

#ifdef WIN32
		pqxx::connection c{"postgresql://postgres:gb6205966@localhost/postgres"};
#else
		pqxx::connection c{"postgresql://postgres:bingfao@localhost/kingxun"};
#endif
		pqxx::work tx{c};
		KxDevStatusPacketBody_Base *pDevStatus = (KxDevStatusPacketBody_Base *)msgPacket.getMsgBodyBuf();

		// KX_LOG_FUNC_((unsigned char *)pDevStatus, sizeof(KxDevStatusPacketBody_Base));

		// auto tm_now = std::localtime(&t_c);
		// std::string strnow = std::format("{:d}-{:d}-{:d} {:d}:{:d}:{:d}", tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);

		std::string strsql;
		int batstid = -1;
		unsigned int *pStatusLow = (unsigned int *)(&pDevStatus->Status);
		unsigned short *pStatusHigh = (unsigned short *)(pStatusLow + 1);
		// pDevStatus->miniBatteryStatus;
		//  先写入batterystatus
		std::string strSeriesData = "NULL";
		if (pDevStatus->batteryExist)
		{
			auto &batteryStatus = pDevStatus->batteryStatus;
			if (pDevStatus->seriesCount)
			{
				// KxDev_BatterySerieData_ *pSerieData = &pDevStatus->seriesData;
				unsigned char *pSeriesBytes = (unsigned char *)(&pDevStatus->seriesData);
				std::stringstream ss;
				auto nSeriesDataBytes = sizeof(KxDev_BatterySerieData_) * pDevStatus->seriesCount;
				for (int i = 0; i < nSeriesDataBytes; ++i)
				{
					ss << std::setw(2) << std::setfill('0') << std::hex << (short)pSeriesBytes[i];
				}
				strSeriesData = "'\\x" + ss.str() + "'";
			}
			// else
			// {
			// 	strsql = std::format("Insert into batterystatus (batteryid,socpercent,voltage,temp,currentflag,current,seriescount,stTime) values ('{:s}',{:d},{:d},{:d},{:d},{:d},{:d},localtimestamp({:d}) ) RETURNING batstid;",
			// 						 pDevStatus->szBatteryId, batteryStatus.socPercent, batteryStatus.voltage, batteryStatus.temp,
			// 						 batteryStatus.currentFlag, batteryStatus.current, pDevStatus->seriesCount, t_c);
			// }
			char szBatteryid[sizeof(KxDevStatusPacketBody_Base::szBatteryId) + 1] = {0};
			std::strncpy(szBatteryid, pDevStatus->szBatteryId, sizeof(KxDevStatusPacketBody_Base::szBatteryId));
			strsql = std::format("Insert into batterystatus (batteryid,socpercent,voltage,temp,currentflag,current,seriescount,seriesdata,stTime) values ('{:s}',{:d},{:d},{:d},{:d},{:d},{:d},{:s},localtimestamp({:d})  ) RETURNING batstid;",
								 szBatteryid, batteryStatus.socPercent, batteryStatus.voltage, batteryStatus.temp,
								 batteryStatus.currentFlag, batteryStatus.current, pDevStatus->seriesCount, strSeriesData, t_c);
			// std::cout << "sql is: " << strsql << std::endl;
			// KX_LOG_FUNC_(strsql);
			pqxx::result r = tx.exec(strsql);
			// tx.commit();

			std::size_t const num_rows = std::size(r);
			if (num_rows)
			{
				auto row = r[0];
				pqxx::field const field = row[0];
				batstid = field.as<int>();
			}
		}
		std::string strbastid = "NULL";
		if (batstid != -1)
		{
			strbastid = std::to_string(batstid);
		}
		std::string strbMiniBatId = "NULL";
		std::string strbMiniBatStatus = "NULL";
		char szMiniBatteryId[sizeof(KxDevStatusPacketBody_Base::szMiniBatteryId) + 1] = {0};
		std::strncpy(szMiniBatteryId, pDevStatus->szMiniBatteryId, sizeof(KxDevStatusPacketBody_Base::szMiniBatteryId));
		if (pDevStatus->bMiniBatExist)
		{
			strbMiniBatId = "'";
			strbMiniBatId += szMiniBatteryId;
			strbMiniBatId += "'";
			auto nSeriesDataBytes = sizeof(KxDev_MiniBatteryStatus_);
			unsigned char *pSeriesBytes = (unsigned char *)(&pDevStatus->miniBatteryStatus);
			std::stringstream ss;
			for (int i = 0; i < nSeriesDataBytes; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << (short)pSeriesBytes[i];
			}
			strbMiniBatStatus = "'\\x" + ss.str() + "'";
		}

		strsql = std::format("Insert into devStatus (devId,devType,devpos,mileage,bdriving,speed,status,bminibatexist,minibatteryid,miniibatterystatus,batteryexist,chargeflag,batteryid,batstid,stTime) values ({:d},{:d},'{},{}',{},{},{},'\\x{:0>8x}{:0>4x}',{},{},{},{},{},'{}',{},localtimestamp({:d}) );",
							 msgPacket.getDevId(),
							 pDevStatus->nDevType, pDevStatus->lngPos, pDevStatus->latPos, pDevStatus->mileage, pDevStatus->bDriving, pDevStatus->speed,
							 *pStatusLow, *pStatusHigh, pDevStatus->bMiniBatExist, strbMiniBatId, strbMiniBatStatus, pDevStatus->batteryExist, pDevStatus->chargeFlag, pDevStatus->szBatteryId, batstid, t_c);
		// KX_LOG_FUNC_(strsql);
		// std::cout << "sql is: " << strsql << std::endl;
		tx.exec(strsql);
		tx.commit();
	}
	catch (std::exception const &e)
	{
		// std::cerr << "ERROR: " << e.what() << std::endl;
		std::string strLog = "ERROR: ";
		strLog += e.what();
		KX_LOG_FUNC_(strLog);
	}
#endif
}

void KxBusinessLogicMgr::DevUsedTrafficMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	KxMsgHeader_Base msgRespHead_base;
	auto msgHeader = msgPacket.getMsgHeader();
	msgRespHead_base.nMsgId = msgHeader.nMsgId;
	msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
	msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
	msgRespHead_base.nMsgBodyLen = 0;
	msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
	session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, nullptr, false);
	// const std::chrono::time_point<std::chrono::system_clock> tp_now =
	// 	std::chrono::system_clock::now();
	// const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
	const std::time_t t_c = std::time(nullptr);
	session->setLastTime(t_c);
#ifdef USING_PQ_DB_
	try
	{
		// pqxx::connection c{"host=localhost port=5432 dbname=kingxun user=postgres password=bingfao"};

#ifdef WIN32
		pqxx::connection c{"postgresql://postgres:gb6205966@localhost/postgres"};
#else
		pqxx::connection c{"postgresql://postgres:bingfao@localhost/kingxun"};
#endif
		pqxx::work tx{c};
		KxDevUsedTrafficPacketBody *pBody = (KxDevUsedTrafficPacketBody *)msgPacket.getMsgBodyBuf();

		std::string strsql;

		strsql = std::format("Insert into devusedtraffic (devId,devType,\"usedTraffic\",stTime) values ({},{:d},{},localtimestamp({:d}) );",
							 msgPacket.getDevId(), pBody->nDevType, pBody->nUsedTraffic, t_c);

		// std::cout << "sql is: " << strsql << std::endl;
		tx.exec(strsql);
		// tx.commit();

		// 根据流量计算，是否通知2022
		strsql = std::format("Select filetype,filename,\"fileURL\",\"fileSize\",\"fileMD5\" from devFileUpdateTaskRecView where devid={} and devtype={} and updatedtime is NULL limit 1;",
							 msgPacket.getDevId(), pBody->nDevType);
		KX_LOG_FUNC_(strsql);
		auto rdev = tx.exec(strsql);
		if (rdev.size() > 0)
		{
			auto row_ = rdev[0];
			auto filetype = row_[0].as<short>();
			auto filename = row_[1].as<std::string>();
			auto fileURL = row_[2].as<std::string>();
			auto fileSize = row_[3].as<int>();

			unsigned char szMsgBuf[256] = {0};
			KxDevFileUpdateNotify_OrMsg notify_msg;
			notify_msg.FileType = filetype;
			std::strncpy(notify_msg.szFileName, filename.c_str(), sizeof(notify_msg.szFileName));
			notify_msg.svrTime = t_c;
			notify_msg.nSessionId = session->GetSessionId();
			notify_msg.nFileLen = fileSize;

			if (!row_[4].is_null())
			{
				auto filemd5 = row_[4].as<pqxx::bytes>();
				std::memcpy(notify_msg.fileMd5, filemd5.data(), sizeof(notify_msg.fileMd5));
			}
			// 计算出URL的md5
			int nMdLen = sizeof(notify_msg.fileURL_KEY);
			Kx_MD5((unsigned char *)fileURL.c_str(), fileURL.length(), notify_msg.fileURL_KEY, nMdLen);
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *pOrDevMsg = (unsigned char *)&notify_msg;
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_FILETOUPDATE_NOTIFY;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;
			msgDevReqHead_base.nMsgBodyLen = 0;
			msgDevReqHead_base.nCryptFlag = 1;
			bool brt = session->AES_encrypt(pOrDevMsg, sizeof(notify_msg), msgBody, nBufLen);
			if (brt)
			{
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(notify_msg);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(pOrDevMsg, sizeof(notify_msg));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgDevReqHead_base.nMsgBodyLen = nBufLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendMsgPacket(msgDevReqHead_base, msgBody, true);
			}
		}
		tx.commit();
	}
	catch (std::exception const &e)
	{
		// std::cerr << "ERROR: " << e.what() << std::endl;
		std::string strLog = "ERROR: ";
		strLog += e.what();
		KX_LOG_FUNC_(strLog);
	}
#endif
}

void KxBusinessLogicMgr::DevGetFileDataMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	// to be modify

	KxMsgHeader_Base msgRespHead_base;
	auto msgHeader = msgPacket.getMsgHeader();
	msgRespHead_base.nMsgId = msgHeader.nMsgId;
	msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
	msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
	msgRespHead_base.nMsgBodyLen = 0;
	msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));

	// const std::chrono::time_point<std::chrono::system_clock> tp_now =
	// 	std::chrono::system_clock::now();
	// const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
	const std::time_t t_c = std::time(nullptr);
	session->setLastTime(t_c);
#ifdef USING_PQ_DB_
	try
	{
		// pqxx::connection c{"host=localhost port=5432 dbname=kingxun user=postgres password=bingfao"};

#ifdef WIN32
		pqxx::connection c{"postgresql://postgres:gb6205966@localhost/postgres"};
#else
		pqxx::connection c{"postgresql://postgres:bingfao@localhost/kingxun"};
#endif
		pqxx::work tx{c};
		KxDevGet_FileData_Msg *pBody = (KxDevGet_FileData_Msg *)msgPacket.getMsgBodyBuf();

		std::string strsql;

		char szFileName[50] = {0};
		std::strncpy(szFileName, pBody->szFileName, sizeof(pBody->szFileName));
		// 根据流量计算，是否通知2022
		strsql = std::format("Select \"fileURL\",\"fileSize\",\"fileMD5\" \
		 from devFileUpdateTaskRecView where devid={} and devtype={} and filetype={} and filename= '{}' and updatedtime is NULL limit 1;",
							 msgPacket.getDevId(), pBody->nDevType, pBody->FileType, szFileName);
		KX_LOG_FUNC_(strsql);
		auto rdev = tx.exec(strsql);
		if (rdev.size() > 0)
		{
			auto row_ = rdev[0];
			auto fileURL = row_[0].as<std::string>();
			auto fileSize = row_[1].as<int>();
			auto fileMD5 = row_[2].as<pqxx::bytes>();
			unsigned char url_md5[16] = {0};
			int nMd5Len = sizeof(url_md5);
			Kx_MD5((unsigned char *)fileURL.c_str(), fileURL.length(), url_md5, nMd5Len);
			if (0 == std::memcmp(url_md5, pBody->fileURL_KEY, sizeof(url_md5)))
			{
				if (pBody->nFileDataPos + pBody->nDataLen <= fileSize)
				{
					unsigned int nFileSize(0);
					std::string strFileData;
					if (std::ifstream is{fileURL, std::ios::binary | std::ios::ate})
					{
						auto size = is.tellg();
						nFileSize = size;
						if (nFileSize == fileSize)
						{
							strFileData.assign(size, '\0'); // construct string to stream size
							is.seekg(0);
							if (is.read(&strFileData[0], size))
							{
								// 计算md5
								unsigned char cal_fileMd5[16] = {0};
								int nMdLen = sizeof(cal_fileMd5);
								Kx_MD5((unsigned char *)strFileData.c_str(), nFileSize,
									   cal_fileMd5, nMdLen);
								// KX_LOG_FUNC_(fileMd5, nMdLen);
								if (0 == std::memcmp(cal_fileMd5, fileMD5.data(), sizeof(cal_fileMd5)))
								{
									msgRespHead_base.nMsgBodyLen = pBody->nDataLen + sizeof(KxDev_FileData_Msg_Base) - 1;
									unsigned char *pFileData = new unsigned char[msgRespHead_base.nMsgBodyLen];
									if (pFileData)
									{
										KxDev_FileData_Msg_Base &msg_Data = *(KxDev_FileData_Msg_Base *)(pFileData);
										msg_Data.nFileDataPos = pBody->nFileDataPos;
										msg_Data.nDataLen = pBody->nDataLen;
										std::memcpy(msg_Data.fileData, &strFileData[pBody->nFileDataPos], pBody->nDataLen);
										int ncrc_len = msgRespHead_base.nMsgBodyLen - sizeof(unsigned short);
										unsigned short *pMsg_Crc16 = (unsigned short *)(pFileData + ncrc_len);
										*pMsg_Crc16 = crc16_ccitt(pFileData, ncrc_len);
										session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, pFileData, true);
										delete[] pFileData;
										pFileData = nullptr;
									}
								}
							}
						}
						is.close();
					}
				}
				else
				{
					session->SendRespPacket(msgRespHead_base, cst_nResp_Code_PARA_ERR, nullptr, false);
				}
			}
		}
		tx.commit();
	}
	catch (std::exception const &e)
	{
		// std::cerr << "ERROR: " << e.what() << std::endl;
		std::string strLog = "ERROR: ";
		strLog += e.what();
		KX_LOG_FUNC_(strLog);
	}
#endif
}

void KxBusinessLogicMgr::AppCtrlLockDevMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// 先解密
	unsigned char *originMsgBody = nullptr;
	unsigned int nMsgBufLen = 0;
	bool brt = session->checkAESPacketData(pMsgBody, msgHeader.nMsgBodyLen, originMsgBody, nMsgBufLen);
	if (brt && originMsgBody && nMsgBufLen)
	{
		KxAppDevCtrlLockDev_OrMsg *pOriginMsg = (KxAppDevCtrlLockDev_OrMsg *)originMsgBody;

		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);
		// 先发送到dev
		// 查找对应的dev 的 session

		unsigned int nDevId = pOriginMsg->nDevId;
		auto devSession = session->getDevSession(nDevId);
		if (devSession)
		{
			// 需要做加密
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_LOCKDEV;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;
			msgDevReqHead_base.nMsgBodyLen = 0;
			msgDevReqHead_base.nCryptFlag = 1;
			KxDevCtrlLockDev_OrMsg orimsg;
			orimsg.svrTime = pOriginMsg->svrTime;
			orimsg.nSessionId = devSession->GetSessionId();
			orimsg.nVoiceIndex = pOriginMsg->nVoiceIndex;
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *pOrDevMsg = (unsigned char *)&orimsg;
			brt = devSession->AES_encrypt(pOrDevMsg, sizeof(orimsg), msgBody, nBufLen);
			if (brt)
			{
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(orimsg);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(pOrDevMsg, sizeof(orimsg));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgDevReqHead_base.nMsgBodyLen = nBufLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
				devSession->SendMsgPacket(msgDevReqHead_base, msgBody, true, std::make_shared<KxBussinessLogicNode>(session, msgP));
			}
			else
			{
				// cst_nResp_Code_SEND_DEV_ERR
				KxMsgHeader_Base msgRespHead_base;
				// auto msgHeader = msgPacket.getMsgHeader();
				msgRespHead_base.nMsgId = msgHeader.nMsgId;
				msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
				msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
				msgRespHead_base.nMsgBodyLen = 0;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
			}
		}
		else
		{
			KxMsgHeader_Base msgRespHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			msgRespHead_base.nMsgBodyLen = 0;
			msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
			session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEV_OFFLINE, nullptr, false);
		}
		delete[] originMsgBody;
		originMsgBody = nullptr;
	}
}

void KxBusinessLogicMgr::AppCtrlDevGuardMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// 先解密
	unsigned char *originMsgBody = nullptr;
	unsigned int nMsgBufLen = 0;
	bool brt = session->checkAESPacketData(pMsgBody, msgHeader.nMsgBodyLen, originMsgBody, nMsgBufLen);
	if (brt && originMsgBody && nMsgBufLen)
	{
		KxAppDevCtrlDevGuard_OrMsg *pOriginMsg = (KxAppDevCtrlDevGuard_OrMsg *)originMsgBody;

		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);
		// 先发送到dev
		// 查找对应的dev 的 session

		unsigned int nDevId = pOriginMsg->nDevId;
		auto devSession = session->getDevSession(nDevId);
		if (devSession)
		{
			// 需要做加密
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_LOCKDEV;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;
			msgDevReqHead_base.nMsgBodyLen = 0;
			msgDevReqHead_base.nCryptFlag = 1;
			KxDevCtrlDevGuard_OrMsg orimsg;
			orimsg.svrTime = pOriginMsg->svrTime;
			orimsg.nSessionId = devSession->GetSessionId();
			orimsg.MotorPowerFlag = pOriginMsg->MotorPowerFlag;
			orimsg.nMaxSpeed = pOriginMsg->nMaxSpeed;
			orimsg.nVoiceIndex = pOriginMsg->nVoiceIndex;
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *pOrDevMsg = (unsigned char *)&orimsg;
			brt = devSession->AES_encrypt(pOrDevMsg, sizeof(orimsg), msgBody, nBufLen);
			if (brt)
			{
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(orimsg);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(pOrDevMsg, sizeof(orimsg));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgDevReqHead_base.nMsgBodyLen = nBufLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
				devSession->SendMsgPacket(msgDevReqHead_base, msgBody, true, std::make_shared<KxBussinessLogicNode>(session, msgP));
			}
			else
			{
				// cst_nResp_Code_SEND_DEV_ERR
				KxMsgHeader_Base msgRespHead_base;
				auto msgHeader = msgPacket.getMsgHeader();
				msgRespHead_base.nMsgId = msgHeader.nMsgId;
				msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
				msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
				msgRespHead_base.nMsgBodyLen = 0;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
			}
		}
		else
		{
			KxMsgHeader_Base msgRespHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			msgRespHead_base.nMsgBodyLen = 0;
			msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
			session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEV_OFFLINE, nullptr, false);
		}
		delete[] originMsgBody;
		originMsgBody = nullptr;
	}
}

void KxBusinessLogicMgr::AppCtrlOpenLockMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// 先解密
	unsigned char *originMsgBody = nullptr;
	unsigned int nMsgBufLen = 0;
	bool brt = session->checkAESPacketData(pMsgBody, msgHeader.nMsgBodyLen, originMsgBody, nMsgBufLen);
	if (brt && originMsgBody && nMsgBufLen)
	{
		KxAppDevCtrlOpenLock_OrMsg *pOriginMsg = (KxAppDevCtrlOpenLock_OrMsg *)originMsgBody;

		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);
		// 先发送到dev
		// 查找对应的dev 的 session

		unsigned int nDevId = pOriginMsg->nDevId;
		auto devSession = session->getDevSession(nDevId);
		if (devSession)
		{
			// 需要做加密
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_OPENLOCK;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;
			msgDevReqHead_base.nMsgBodyLen = 0;
			msgDevReqHead_base.nCryptFlag = 1;
			KxDevCtrlOpenLock_OrMsg orimsg;
			orimsg.nAlowTime = pOriginMsg->nAlowTime;
			orimsg.nFarthestDist = pOriginMsg->nFarthestDist;
			orimsg.nLowestSocP = pOriginMsg->nLowestSocP;
			orimsg.svrTime = pOriginMsg->svrTime;
			orimsg.nSessionId = devSession->GetSessionId();
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *pOrDevMsg = (unsigned char *)&orimsg;
			brt = devSession->AES_encrypt(pOrDevMsg, sizeof(orimsg), msgBody, nBufLen);
			if (brt)
			{
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(orimsg);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(pOrDevMsg, sizeof(orimsg));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgDevReqHead_base.nMsgBodyLen = nBufLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
				devSession->SendMsgPacket(msgDevReqHead_base, msgBody, true, std::make_shared<KxBussinessLogicNode>(session, msgP));
			}
			else
			{
				// cst_nResp_Code_SEND_DEV_ERR
				KxMsgHeader_Base msgRespHead_base;
				auto msgHeader = msgPacket.getMsgHeader();
				msgRespHead_base.nMsgId = msgHeader.nMsgId;
				msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
				msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
				msgRespHead_base.nMsgBodyLen = 0;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
			}
		}
		else
		{
			KxMsgHeader_Base msgRespHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			msgRespHead_base.nMsgBodyLen = 0;
			msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
			session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEV_OFFLINE, nullptr, false);
		}
		delete[] originMsgBody;
		originMsgBody = nullptr;
	}
}

void KxBusinessLogicMgr::AppCtrlDevElecLockCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// 先解密
	unsigned char *originMsgBody = nullptr;
	unsigned int nMsgBufLen = 0;
	bool brt = session->checkAESPacketData(pMsgBody, msgHeader.nMsgBodyLen, originMsgBody, nMsgBufLen);
	if (brt && originMsgBody && nMsgBufLen)
	{
		KxAppDevCtrlElecLock_OrMsg *pOriginMsg = (KxAppDevCtrlElecLock_OrMsg *)originMsgBody;

		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);
		// 先发送到dev
		// 查找对应的dev 的 session

		unsigned int nDevId = pOriginMsg->nDevId;
		auto devSession = session->getDevSession(nDevId);
		if (devSession)
		{
			// 需要做加密
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_OPENELECLOCK;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;
			msgDevReqHead_base.nMsgBodyLen = 0;
			KxDevCtrlElecLock_OrMsg orimsg;
			orimsg.lockFlag = pOriginMsg->lockFlag;
			orimsg.svrTime = pOriginMsg->svrTime;
			orimsg.nSessionId = devSession->GetSessionId();
			unsigned char msgBody[256] = {0};
			unsigned int nBufLen = sizeof(msgBody);
			unsigned char *pOrDevMsg = (unsigned char *)&orimsg;
			brt = devSession->AES_encrypt(pOrDevMsg, sizeof(orimsg), msgBody, nBufLen);
			if (brt)
			{
				unsigned int *pData = (unsigned int *)(msgBody + nBufLen);
				*pData = sizeof(orimsg);
				nBufLen += sizeof(unsigned int);
				unsigned short nCrc16 = crc16_ccitt(pOrDevMsg, sizeof(orimsg));
				*(unsigned short *)(msgBody + nBufLen) = nCrc16;
				nBufLen += sizeof(unsigned short);
				msgDevReqHead_base.nMsgBodyLen = nBufLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
				devSession->SendMsgPacket(msgDevReqHead_base, msgBody, true, std::make_shared<KxBussinessLogicNode>(session, msgP));
			}
			else
			{
				// cst_nResp_Code_SEND_DEV_ERR
				KxMsgHeader_Base msgRespHead_base;
				// auto msgHeader = msgPacket.getMsgHeader();
				msgRespHead_base.nMsgId = msgHeader.nMsgId;
				msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
				msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
				msgRespHead_base.nMsgBodyLen = 0;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
			}
		}
		else
		{
			KxMsgHeader_Base msgRespHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			msgRespHead_base.nMsgBodyLen = 0;
			msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
			session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEV_OFFLINE, nullptr, false);
		}
		delete[] originMsgBody;
		originMsgBody = nullptr;
	}
}

void KxBusinessLogicMgr::AppCtrlDevFileDeliverCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	auto msgHeader = msgPacket.getMsgHeader();
	auto pMsgBody = msgPacket.getMsgBodyBuf();
	// bool brt=false;
	if (msgHeader.nMsgBodyLen >= sizeof(KxAppDevCtrlFileDeliver_Base))
	{
		const std::time_t t_c = std::time(nullptr);
		session->setLastTime(t_c);

		KxAppDevCtrlFileDeliver_Base *pFileDeliver = (KxAppDevCtrlFileDeliver_Base *)pMsgBody;
		unsigned int nFileLen = pFileDeliver->nFileLen;
		unsigned int nHeaderLen = nFileLen;
		// 查找对应的dev 的 session
		unsigned int nDevId = pFileDeliver->nDevId;
		auto devSession = session->getDevSession(nDevId);
		if (devSession)
		{
			// 根据文件长度，分2020/2021下发
			if (nFileLen > FILE_DATA_HEADER_ALLOW_LEN)
			{
				nHeaderLen = FILE_DATA_HEADER_ALLOW_LEN;
			}
			// 先发送2020
			// 需要做加密
			KxMsgHeader_Base msgDevReqHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgDevReqHead_base.nMsgId = MSG_DEVCTRL_FILEDELIVER_HEADER;
			msgDevReqHead_base.nSeqNum = msgHeader.nSeqNum;
			msgDevReqHead_base.nTypeFlag = 0;

			const unsigned int nBufLen = sizeof(KxDevCtrlFileDeliverHeader_OrMsg_Base) + nHeaderLen - FILE_DATA_BASE_LEN;
			unsigned char szOriMsg[FILE_DATA_HEADER_ALLOW_LEN + FILE_DATA_BASE_LEN] = {0};
			unsigned char *pOriMsg = szOriMsg;

			// unsigned char *pOriMsg = new unsigned char[nBufLen + FILE_DATA_BASE_LEN];
			bool brt(false);
			// if (pOriMsg)
			// {
			KxDevCtrlFileDeliverHeader_OrMsg_Base &orimsg = *(KxDevCtrlFileDeliverHeader_OrMsg_Base *)pOriMsg;
			orimsg.svrTime = pFileDeliver->svrTime;
			auto devSessionId = devSession->GetSessionId();
			orimsg.nSessionId = devSessionId;
			orimsg.FileType = pFileDeliver->FileType;
			std::strncpy(orimsg.szFileName, pFileDeliver->szFileName, sizeof(orimsg.szFileName));
			orimsg.nFileLen = nFileLen;
			std::memcpy(orimsg.fileMd5, pFileDeliver->fileMd5, 16 + nHeaderLen);

			// unsigned int nBlocks = (nBufLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
			// unsigned int nMsgDataLen = nBlocks * AES_BLOCK_SIZE;

			unsigned char szMsgBody[FILE_DATA_HEADER_ALLOW_LEN + FILE_DATA_BASE_LEN] = {0};
			unsigned int nMsgDataLen = sizeof(szMsgBody);
			unsigned char *pMsgFileBody = szMsgBody;

			// unsigned char *pMsgFileBody = new unsigned char[nMsgDataLen + sizeof(int) + sizeof(short) + FILE_DATA_BASE_LEN];
			// if (pMsgFileBody)
			// {
			brt = devSession->AES_encrypt(pOriMsg, nBufLen, pMsgFileBody, nMsgDataLen);
			// std::stringstream ss_log;
			// ss_log << "AES_encrypt, nBufLen: " << nBufLen << ", nMsgDataLen: " << nMsgDataLen << std::endl;
			// KX_LOG_FUNC_(ss_log.str());
			if (brt)
			{
				// KX_LOG_FUNC_(pOriMsg,nBufLen);
				unsigned int *pData = (unsigned int *)(pMsgFileBody + nMsgDataLen);
				*pData = nBufLen;
				nMsgDataLen += sizeof(int);
				unsigned short nCrc16 = crc16_ccitt(pOriMsg, nBufLen);
				*(unsigned short *)(pMsgFileBody + nMsgDataLen) = nCrc16;
				nMsgDataLen += sizeof(unsigned short);
				msgDevReqHead_base.nCryptFlag = 1;
				msgDevReqHead_base.nMsgBodyLen = nMsgDataLen;
				msgDevReqHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevReqHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				// auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
				// auto LogicNode = std::make_shared<KxBussinessLogicNode>(session, msgP);

				devSession->SendMsgPacket(msgDevReqHead_base, pMsgFileBody, true);
				std::this_thread::sleep_for(20ms);

				nFileLen -= nHeaderLen;
				unsigned int nFileDataPos = nHeaderLen;
				// 再继续发送2021报文
				unsigned int nFilePacketLen(0);
				KxMsgHeader_Base msgDevDeliverFile_base;
				// auto msgHeader = msgPacket.getMsgHeader();
				msgDevDeliverFile_base.nMsgId = MSG_DEVCTRL_FILEDELIVER_DATA;
				msgDevDeliverFile_base.nSeqNum = msgHeader.nSeqNum;
				msgDevDeliverFile_base.nTypeFlag = 0;
				unsigned char szMsgBody_FileData[cst_FILE_DATA_PACKET_ALLOW_LEN + FILE_DATA_BASE_LEN] = {0};
				unsigned char *pMsgBody_FileData = szMsgBody_FileData;
				KxDevCtrlFileDeliverFileData_Base &deliverFileData = *(KxDevCtrlFileDeliverFileData_Base *)pMsgBody_FileData;
				while (nFileLen > 0)
				{
					// 等待继续处理.....
					if (nFileLen > cst_FILE_DATA_PACKET_ALLOW_LEN)
					{
						nFilePacketLen = cst_FILE_DATA_PACKET_ALLOW_LEN;
					}
					else
					{
						nFilePacketLen = nFileLen;
					}
					unsigned int nMsgPacketBodyLen = sizeof(KxDevCtrlFileDeliverFileData_Base) + nFilePacketLen - 1;

					// unsigned char *pMsgBody_FileData = new unsigned char[nMsgPacketBodyLen + FILE_DATA_BASE_LEN];
					// if (pMsgBody_FileData)
					//{
					deliverFileData.nSessionId = devSessionId;
					deliverFileData.FileType = orimsg.FileType;
					std::strncpy(deliverFileData.szFileName, orimsg.szFileName, sizeof(deliverFileData.szFileName));
					deliverFileData.nFileDataPos = nFileDataPos;
					deliverFileData.nDataLen = (unsigned short)nFilePacketLen;
					unsigned char *pFileData = pFileDeliver->szFileData + nFileDataPos;
					std::memcpy(deliverFileData.fileData, pFileData, nFilePacketLen);

					unsigned short *pCRC16 = (unsigned short *)(deliverFileData.fileData + nFilePacketLen);
					*pCRC16 = crc16_ccitt((unsigned char *)&deliverFileData.nFileDataPos, sizeof(int) + sizeof(short) + nFilePacketLen);

					msgDevDeliverFile_base.nMsgBodyLen = nMsgPacketBodyLen;
					++msgDevDeliverFile_base.nSeqNum;
					msgDevDeliverFile_base.nCrc16 = crc16_ccitt((unsigned char *)&msgDevDeliverFile_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));

					devSession->SendMsgPacket(msgDevDeliverFile_base, pMsgBody_FileData, true);

					nFileLen -= nFilePacketLen;
					nFileDataPos += nFilePacketLen;

					std::stringstream ss_log;
					ss_log << "nMsgPacketBodyLen: " << nMsgPacketBodyLen << ", nFileDataPos: " << nFileDataPos << ", nFilePacketLen: " << nFilePacketLen;
					KX_LOG_FUNC_(ss_log.str());

					// KX_LOG_FUNC_(pMsgBody_FileData,nMsgPacketBodyLen);

					std::this_thread::sleep_for(80ms);

					// KX_LOG_FUNC_("Call delete[] pMsgBody_FileData");
					// delete[] pMsgBody_FileData;
					// pMsgBody_FileData = nullptr;
					// KX_LOG_FUNC_("After Call delete[] pMsgBody_FileData");
					// }
					// else
					// {
					// 	break;
					// }
				}
			}
			// KX_LOG_FUNC_("Call delete[] pMsgBody");
			// delete[] pMsgBody;
			// pMsgBody = nullptr;
			// KX_LOG_FUNC_("After Call delete[] pMsgBody");
			//}
			// KX_LOG_FUNC_("Call delete[] pOriMsg");
			// delete[] pOriMsg;
			// pOriMsg = nullptr;
			// KX_LOG_FUNC_("After Call delete[] pOriMsg");
			//}
			if (!brt)
			{
				// cst_nResp_Code_SEND_DEV_ERR
				KxMsgHeader_Base msgRespHead_base;
				// auto msgHeader = msgPacket.getMsgHeader();
				msgRespHead_base.nMsgId = msgHeader.nMsgId;
				msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
				msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
				msgRespHead_base.nMsgBodyLen = 0;
				msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
				session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
			}
		}
		else
		{
			KxMsgHeader_Base msgRespHead_base;
			// auto msgHeader = msgPacket.getMsgHeader();
			msgRespHead_base.nMsgId = msgHeader.nMsgId;
			msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
			msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
			msgRespHead_base.nMsgBodyLen = 0;
			msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
			session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEV_OFFLINE, nullptr, false);
		}
	}
}

KxBusinessLogicMgr &KxBusinessLogicMgr::GetInstance()
{
	static KxBusinessLogicMgr instance;
	return instance;
}