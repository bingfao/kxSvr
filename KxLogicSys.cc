#include "KxLogicSys.hpp"
#include "KxMsgNode.hpp"
#include "KxSession.hpp"
#include "KxLogger.hpp"

#ifdef USING_PQ_DB_
#include <pqxx/pqxx>
#endif

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
	m_map_FunCallbacks[MSG_APP_DEVCTRL_OPENLOCK] = std::bind(&KxBusinessLogicMgr::AppDevCtrlMsgCallBack, this,
															 std::placeholders::_1, std::placeholders::_2);
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

		msgRespHead_base.nMsgBodyLen = 4;
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		unsigned int nBodySessionId = session->GetSessionId();
		auto nDevId = msgPacket.getDevId();
		session->updateDevSessionId(nDevId, nBodySessionId);
		session->SendRespPacket(msgRespHead_base, cst_nResp_Code_OK, (unsigned char *)&nBodySessionId, true);
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
			strsql = std::format("Insert into batterystatus (batteryid,socpercent,voltage,temp,currentflag,current,seriescount,seriesdata,stTime) values ('{:s}',{:d},{:d},{:d},{:d},{:d},{:d},{:s},localtimestamp({:d})  ) RETURNING batstid;",
								 pDevStatus->szBatteryId, batteryStatus.socPercent, batteryStatus.voltage, batteryStatus.temp,
								 batteryStatus.currentFlag, batteryStatus.current, pDevStatus->seriesCount, strSeriesData, t_c);
			// std::cout << "sql is: " << strsql << std::endl;
			KX_LOG_FUNC_(strsql);
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
		if (pDevStatus->bMiniBatExist)
		{
			strbMiniBatId = "'";
			strbMiniBatId += pDevStatus->szMiniBatteryId;
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
		strsql = std::format("Insert into devStatus (devId,devType,devpos,bdriving,speed,status,bminibatexist,minibatteryid,miniibatterystatus,batteryexist,chargeflag,batteryid,batstid,stTime) values ({:d},{:d},'{},{}',{},{},'\\x{:0>8x}{:0>4x}',{},{},{},{},{},'{}',{},localtimestamp({:d}) );",
							 msgPacket.getDevId(),
							 pDevStatus->nDevType, pDevStatus->lngPos, pDevStatus->latPos, pDevStatus->bDriving, pDevStatus->speed,
							 *pStatusLow, *pStatusHigh, pDevStatus->bMiniBatExist, strbMiniBatId,strbMiniBatStatus, pDevStatus->batteryExist, pDevStatus->chargeFlag, pDevStatus->szBatteryId, batstid, t_c);
		KX_LOG_FUNC_(strsql);
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

void KxBusinessLogicMgr::AppDevCtrlMsgCallBack(std::shared_ptr<KxDevSession> session, const KxMsgPacket_Basic &msgPacket)
{
	const std::chrono::time_point<std::chrono::system_clock> tp_now =
		std::chrono::system_clock::now();
	const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
	session->setLastTime(t_c);
	// 先发送到dev
	// 查找对应的dev 的 session
	KxAppDevCtrlOpenLockPacketBody *pBody = (KxAppDevCtrlOpenLockPacketBody *)msgPacket.getMsgBodyBuf();
	unsigned int nDevId = pBody->nDevId;
	auto devSession = session->getDevSession(nDevId);
	if (devSession)
	{
		KxMsgHeader_Base msgRespHead_base;
		auto msgHeader = msgPacket.getMsgHeader();
		msgRespHead_base.nMsgId = MSG_DEVCTRL_OPENLOCK;
		msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
		msgRespHead_base.nTypeFlag = 0;
		msgRespHead_base.nMsgBodyLen = 0;
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		auto msgP = std::make_shared<KxMsgPacket_Basic>(msgPacket);
		devSession->SendMsgPacket(msgRespHead_base, nullptr, false, std::make_shared<KxBussinessLogicNode>(session, msgP));
	}
	else
	{
		KxMsgHeader_Base msgRespHead_base;
		auto msgHeader = msgPacket.getMsgHeader();
		msgRespHead_base.nMsgId = msgHeader.nMsgId;
		msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
		msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
		msgRespHead_base.nMsgBodyLen = 0;
		msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
		session->SendRespPacket(msgRespHead_base, cst_nResp_Code_DEVID_ERR, nullptr, false);
	}
}

KxBusinessLogicMgr &KxBusinessLogicMgr::GetInstance()
{
	static KxBusinessLogicMgr instance;
	return instance;
}