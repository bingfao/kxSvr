#include "KxSession.hpp"
#include "kxSvr.hpp"
#include "KxLogicSys.hpp"
#include "KxLogger.hpp"
#include "aeshelper.hpp"
#ifdef USING_PQ_DB_
#include <pqxx/pqxx>
#endif

#if defined(ASIO_ENABLE_HANDLER_TRACKING)
#define use_awaitable \
	asio::use_awaitable_t(__FILE__, __LINE__, __PRETTY_FUNCTION__)
#endif

constexpr int MAX_SENDQUE = 100;

KxDevSession::KxDevSession(asio::io_context &io_context, KxServer *server)
	: m_io_context(io_context), m_socket(io_context), m_server(server), m_b_close(false), m_nSessionId(0)
{
}

KxDevSession::~KxDevSession()
{
	try
	{
		// std::cout << "~KxSession destruct " << std::hex << m_nSessionId << std::dec << std::endl;
		KX_LOG_FUNC_(std::format("~KxSession destruct sessionId: 0x{:x}", m_nSessionId));
		Close();
		// std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	catch (std::exception &exp)
	{
		// std::cout << "exception is " << exp.what() << std::endl;
		KX_LOG_FUNC_(std::format("~KxSession destruct sessionId: 0x{:x} exception: {}", m_nSessionId, exp.what()));
	}
}

void KxDevSession::Close()
{
	if (!m_b_close)
	{
		// std::cout << "KxSession Close sessionId:" << std::hex << m_nSessionId << std::dec << std::endl;
		KX_LOG_FUNC_(std::format("KxSession Close sessionId: 0x{:x}", m_nSessionId));
		m_socket.close();
		m_b_close = true;
	}
}

void KxDevSession::HandleRespWrited(const asio::error_code &error, std::shared_ptr<KxDevSession> shared_self)
{
	try
	{
		if (!error)
		{
			std::unique_lock<std::mutex> lock(m_send_mutex);
			bool bDone(false);
			if (!m_svrRespToSend_que.empty())
			{
				auto msg_node = m_svrRespToSend_que.front();
				auto msgnodeHeader = msg_node->getMsgHeader();
				// std::cout << "Resp send OK. MsgId: " << msgnodeHeader.nMsgId << " SessionId: 0x" << std::hex << m_nSessionId << std::dec << std::endl;
				// std::string strLog = "Resp send OK. MsgId: "+std::to_string(msgnodeHeader.nMsgId)+" SessionId: 0x";
				// strLog += std::format("{:X}",m_nSessionId);
				// KX_LOG_FUNC_(strLog);
				KX_LOG_FUNC_(std::format("Resp send OK. MsgId: {:d}  SessionId: 0x{:x}", msgnodeHeader.nMsgId, m_nSessionId));
				m_svrRespToSend_que.pop();
				if (!m_svrRespToSend_que.empty())
				{
					auto msgnode = m_svrRespToSend_que.front();

					std::vector<asio::const_buffer> vec_buf;
					msgnode->getvecBuffer(vec_buf);
					lock.unlock();

					asio::async_write(m_socket, vec_buf,
									  std::bind(&KxDevSession::HandleRespWrited, this, std::placeholders::_1, shared_self));
					bDone = true;
				}
			}
			if (!bDone)
			{
				if (!m_svrMsgToSend_que.empty())
				{
					auto msgnode = m_svrMsgToSend_que.front();
					std::vector<asio::const_buffer> vec_buf;
					msgnode->m_sendPacket->getvecBuffer(vec_buf);
					lock.unlock();
					asio::async_write(m_socket, vec_buf,
									  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, shared_self));
				}
			}
		}
		else
		{
			KX_LOG_FUNC_("HandleRespWrited  failed, error is" + error.message());
			// std::cout << "HandleRespWrited  failed, error is " << error.message() << std::endl;
			Close();
			m_server->ClearSession(m_nSessionId);
		}
	}
	catch (std::exception &e)
	{
		// std::cerr<< "SessionId: " << std::hex << m_nSessionId << std::dec << " HandleRespWrited Exception code : " << e.what() << std::endl;
		KX_LOG_FUNC_(std::format("SessionId: 0x{:X}  HandleRespWrited Exception code : {}", m_nSessionId, e.what()));
		Close();
		m_server->ClearSession(m_nSessionId);
	}
}

void KxDevSession::HandleMsgWrited(const asio::error_code &error, std::shared_ptr<KxDevSession> shared_self)
{
	try
	{
		if (!error)
		{
			std::unique_lock<std::mutex> lock(m_send_mutex);
			bool bDone(false);
			if (!m_svrMsgToSend_que.empty())
			{
				auto logicNode = m_svrMsgToSend_que.front();
				m_server->addSvrMsgWaitResp(logicNode);
				m_svrMsgToSend_que.pop();
				if (!m_svrMsgToSend_que.empty())
				{
					auto msgnode = m_svrMsgToSend_que.front();
					std::vector<asio::const_buffer> vec_buf;
					msgnode->m_sendPacket->getvecBuffer(vec_buf);
					lock.unlock();
					asio::async_write(m_socket, vec_buf,
									  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, shared_self));
				}
			}
			if (!bDone)
			{
				if (!m_svrRespToSend_que.empty())
				{
					auto msgnode = m_svrRespToSend_que.front();
					std::vector<asio::const_buffer> vec_buf;
					msgnode->getvecBuffer(vec_buf);
					lock.unlock();
					asio::async_write(m_socket, vec_buf,
									  std::bind(&KxDevSession::HandleRespWrited, this, std::placeholders::_1, shared_self));
				}
			}
		}
		else
		{
			// std::cout << "HandleMsgWrited  failed, error is " << error.message() << std::endl;
			KX_LOG_FUNC_("HandleMsgWrited  failed, error is" + error.message());
			Close();
			m_server->ClearSession(m_nSessionId);
		}
	}
	catch (std::exception &e)
	{
		// std::cerr << "SessionId: " << std::hex << m_nSessionId << std::dec << " HandleMsgWrited Exception code : " << e.what() << std::endl;
		KX_LOG_FUNC_(std::format("SessionId: 0x{:x}  HandleMsgWrited Exception code : {}", m_nSessionId, e.what()));
		Close();
		m_server->ClearSession(m_nSessionId);
	}
}

bool KxDevSession::checkMsgHeader(const KxMsgHeader_Base &msgHeader_base, unsigned int *pExtData)
{
	bool brt(false);
	unsigned short nCrc16 = crc16_ccitt((unsigned char *)&msgHeader_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
	bool bCrcOk = msgHeader_base.nCrc16 == nCrc16;
	brt = bCrcOk;
	if (msgHeader_base.nTypeFlag == 0)
	{
		if (msgHeader_base.nMsgId != MSG_DEV_REGISTER && msgHeader_base.nMsgId < MSG_APP_DEVCTRL_OPENLOCK)
		{
			if (pExtData[1] != m_nSessionId)
			{
				brt = false;
			}
		}
	}
	return brt;
}

bool KxDevSession::checkAESPacketData(const unsigned char *pBody, unsigned int nBodyLen, unsigned char *&pOrigin, unsigned int &nOriginDataLen)
{
	bool brt(false);
	// 先解密
	unsigned int nAesDataLen = nBodyLen - 6;
	unsigned int nCount = nAesDataLen / AES_IV_BLOCK_SIZE;
	unsigned int nLeft = nAesDataLen % AES_IV_BLOCK_SIZE;
	if (nLeft)
		++nCount;
	nOriginDataLen = nCount * AES_IV_BLOCK_SIZE;
	pOrigin = new unsigned char[nOriginDataLen];
	if (AES_decrypt(pBody, nAesDataLen, pOrigin, nOriginDataLen))
	{
		std::stringstream ssout;
		ssout << "AES_decrypt :" << std::hex;
		for (int i = 0; i < nOriginDataLen; ++i)
		{
			// std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
			ssout << std::setw(2) << std::setfill('0') << (short)pOrigin[i] << ' ';
		}
		// ssout << std::dec << std::endl;
		KX_LOG_FUNC_(ssout.str());

		unsigned short nCrc16 = crc16_ccitt((unsigned char *)pOrigin, nOriginDataLen);
		unsigned int *pDataLen = (unsigned int *)(pBody + nAesDataLen);
		unsigned short *pCrc = (unsigned short *)(pBody + nAesDataLen + 4);
		if (*pCrc == nCrc16 && nOriginDataLen == *pDataLen)
		{
			brt = true;
		}
	}
	return brt;
}

std::shared_ptr<KxDevSession> KxDevSession::getDevSession(unsigned int nDevId)
{
	return m_server->getDevSession(nDevId);
}

void KxDevSession::RandIVData()
{
	Rand_IV_Data(m_aes_iv);
}

void KxDevSession::setAES_Iv(const unsigned char *p)
{
	memcpy(m_aes_iv, p, AES_IV_BLOCK_SIZE);
}

void KxDevSession::setAES_Key(const unsigned char *p)
{
	memcpy(m_aes_key, p, AES_IV_BLOCK_SIZE);
}

bool KxDevSession::AES_encrypt(const unsigned char *pIn, unsigned int nInBufLen,
							   unsigned char *pOut, unsigned int &nOutBufLen)
{
	return aes_128_CBC_encrypt(m_aes_key, m_aes_iv, pIn, nInBufLen, pOut, nOutBufLen);
}

bool KxDevSession::AES_decrypt(const unsigned char *pData, unsigned int nDataLen,
							   unsigned char *pOut, unsigned int &nOutDataLen)
{
	return aes_128_CBC_decrypt(m_aes_key, m_aes_iv, pData, nDataLen, pOut, nOutDataLen);
}

void KxDevSession::getDevAESKeyData()
{
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

		// auto tm_now = std::localtime(&t_c);
		// std::string strnow = std::format("{:d}-{:d}-{:d} {:d}:{:d}:{:d}", tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);

		std::string strsql;

		strsql = std::format("select c.\"commAESKey\" from  vehicles as v left join controlerboardinfo as c on v.controllerid = c.id Where v.devid = {:d} and v.devtype = 1;", m_nDevId);
		KX_LOG_FUNC_(strsql);
		// std::cout << "sql is: " << strsql << std::endl;
		auto rdev = tx.exec(strsql);
		if (rdev.size() > 0)
		{
			auto row_ = rdev[0];
			auto aeskey = row_[0].as<pqxx::bytes>();
			int i = 0;
			for (auto &&byteval : aeskey)
			{
				if (i < AES_IV_BLOCK_SIZE)
					m_aes_key[i++] = std::to_integer<unsigned char>(byteval);
				else
					break;
			}
			std::stringstream ss;
			ss << "0x" << std::hex;
			for (int j = 0; j < AES_IV_BLOCK_SIZE; ++j)
			{
				ss << std::setw(2) << std::setfill('0') << (short)m_aes_key[j] << ' ';
			}
			KX_LOG_FUNC_(ss.str());
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

void KxDevSession::updateDevSessionId(unsigned int nDevId, unsigned int nSessionId)
{
	m_nDevId = nDevId;
	m_server->updateDevSessionIdMap(nDevId, nSessionId);
	// 应该从数据库中获取该DevId对应的 AES_KEY
}

void KxDevSession::setLastTime(const std::time_t &tm_val)
{
	m_tm_last = tm_val;
}

void KxDevSession::checkTimeOut(const std::time_t &tm_val)
{
	if (!m_bWebSvr)
	{
		auto tmdiff = tm_val - m_tm_last;
		if (tmdiff > cst_Client_TimeOut_Sec)
		{
			// std::cout << "KxDevSession timeout sessionId: " << std::hex << m_nSessionId << std::dec << std::endl;
			KX_LOG_FUNC_(std::format("KxDevSession timeout sessionId: 0x{:x}", m_nSessionId));
			Close();
		}
	}
}

void KxDevSession::onPeerClose()
{
	// std::cout << "KxDevSession receive peer closed. sessionId: " << std::hex << m_nSessionId << std::dec << std::endl;
	KX_LOG_FUNC_(std::format("KxDevSession receive peer closed. sessionId: 0x{:x}", m_nSessionId));
	Close();
	std::unique_lock<std::mutex> lock(m_send_mutex);
	while (!m_svrMsgToSend_que.empty())
	{
		m_svrMsgToSend_que.pop();
	}
	m_server->ClearSession(m_nSessionId);
}

void KxDevSession::onMsgResp(std::shared_ptr<KxMsgPacket_Basic> resp)
{
	m_server->onMsgResp(resp);
}

void KxDevSession::Start()
{
	auto shared_this = shared_from_this();
	// 开启接收协程
	asio::co_spawn(m_io_context, [shared_this, this]() -> asio::awaitable<void>
				   {
		try {
			KxMsgHeader_Base msgHeader_base;
			unsigned int nHeaderExtData[2];
			unsigned int nHeaderExtDataLen = 0;
			for (;!m_b_close;) {
				// _recv_head_node->Clear();
				std::size_t n = co_await asio::async_read(m_socket,
					asio::buffer(&msgHeader_base, sizeof(KxMsgHeader_Base)),
					asio::use_awaitable);

				if (n == 0) {
					onPeerClose();
					co_return;
				}
				if (n == sizeof(KxMsgHeader_Base) )
				{
					//判断是否Resp
					if(msgHeader_base.nTypeFlag == cst_Resp_MsgType) {
						nHeaderExtDataLen = 4;
					}
					else{
						nHeaderExtDataLen = 8;
					}
					n = co_await asio::async_read(m_socket,
					asio::buffer(nHeaderExtData, nHeaderExtDataLen),
					asio::use_awaitable);
					if(n == 0) {
						onPeerClose();
						co_return;
					}
					if(n == nHeaderExtDataLen)
					{
						if(checkMsgHeader(msgHeader_base,nHeaderExtData))
						{
							//读出包体
							if(msgHeader_base.nMsgBodyLen)
							{
								if(msgHeader_base.nMsgBodyLen< MAX_LENGTH)
								{
									n = co_await asio::async_read(m_socket,
									asio::buffer(m_dataBuf, msgHeader_base.nMsgBodyLen), asio::use_awaitable);
									if( n ==0 ){
										onPeerClose();
										co_return;
									}
									auto msgPacket = std::make_shared<KxMsgPacket_Basic>(msgHeader_base,nHeaderExtData,m_dataBuf,false);
									
									auto logicNode = std::make_shared<KxBussinessLogicNode>(shared_from_this(),msgPacket);
									KxBusinessLogicMgr::GetInstance().PostMsgToQue(logicNode);
								}
								else{
									//重新new buffer
									auto msgPacket = std::make_shared<KxMsgPacket_Basic>(msgHeader_base,nHeaderExtData,nullptr,true);
									n = co_await asio::async_read(m_socket,
									asio::buffer(msgPacket->getMsgBodyBuf(), msgHeader_base.nMsgBodyLen), asio::use_awaitable);
									if( n ==0 ){
										onPeerClose();
										co_return;
									}
									auto logicNode = std::make_shared<KxBussinessLogicNode>(shared_from_this(),msgPacket);
									KxBusinessLogicMgr::GetInstance().PostMsgToQue(logicNode);
								}
							}
							else
							{
									auto msgPacket = std::make_shared<KxMsgPacket_Basic>(msgHeader_base,nHeaderExtData,nullptr,false);
									
									auto logicNode = std::make_shared<KxBussinessLogicNode>(shared_from_this(),msgPacket);
									KxBusinessLogicMgr::GetInstance().PostMsgToQue(logicNode);
							}
						}
						else{
							// std::cout << "invalid msgHeader is " << msgHeader_base.nMsgId << std::endl;
							KX_LOG_FUNC_(std::format("invalid msgHeader is {:d}",msgHeader_base.nMsgId));
						}
					}
				}			
			}
		}
		catch (std::exception& e) {
			// std::cout << "SessionId: " << std::hex << m_nSessionId << std::dec << " exception is " << e.what() << std::endl;
			KX_LOG_FUNC_(std::format("SessionId: 0x{:x} exception is {}",m_nSessionId,e.what()));
			onPeerClose();
			// Close();
			// m_server->ClearSession(m_nSessionId);
		} }, asio::detached);
}

void KxDevSession::SendRespPacket(const KxMsgHeader_Base &msgHeader, unsigned int nRespCode, unsigned char *pBodyBuf, bool bDelBuf)
{
	std::unique_lock<std::mutex> lock(m_send_mutex);
	auto msgPacket = std::make_shared<KxMsgPacket_Basic>(msgHeader, &nRespCode, pBodyBuf, bDelBuf);
	m_svrRespToSend_que.push(msgPacket);
	auto msgnode = m_svrRespToSend_que.front();
	lock.unlock();
	std::vector<asio::const_buffer> vec_buf;
	msgnode->getvecBuffer(vec_buf);
	asio::async_write(m_socket, vec_buf,
					  std::bind(&KxDevSession::HandleRespWrited, this, std::placeholders::_1, SharedSelf()));
}

void KxDevSession::SendMsgPacket(const KxMsgHeader_Base &msgHeader, unsigned char *pBodyBuf, bool bDelBuf, std::shared_ptr<KxBussinessLogicNode> pLogicNode)
{
	std::unique_lock<std::mutex> lock(m_send_mutex);
	int send_que_size = m_svrMsgToSend_que.size();
	if (send_que_size > MAX_SENDQUE)
	{
		// std::cout << "session: " << m_nSessionId << " send que fulled, size is " << MAX_SENDQUE << std::endl;
		KX_LOG_FUNC_(std::format("Session 0x{:x} send que fulled, size is {:d}", m_nSessionId, MAX_SENDQUE));
		return;
	}
	unsigned int nHeaderExtData[2] = {0, 0};
	nHeaderExtData[1] = m_nSessionId;
	auto msgPacket = std::make_shared<KxMsgPacket_Basic>(msgHeader, nHeaderExtData, pBodyBuf, bDelBuf);
	m_svrMsgToSend_que.push(std::make_shared<KxMsgLogicNode>(msgPacket, pLogicNode));
	auto msgnode = m_svrMsgToSend_que.front();
	std::vector<asio::const_buffer> vec_buf;
	msgnode->m_sendPacket->getvecBuffer(vec_buf);
	lock.unlock();
	asio::async_write(m_socket, vec_buf,
					  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, SharedSelf()));
}

unsigned int KxDevSession::getDevCount()
{
	unsigned int nRt(0);
	if (m_server)
		nRt = m_server->getDevCount();
	return nRt;
}

std::time_t KxDevSession::getSvrStartTime()
{
	std::time_t tc = std::time(nullptr);
	if (m_server)
		tc = m_server->getSvrStartTime();
	return tc;
}
