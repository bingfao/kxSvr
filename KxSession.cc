#include "KxSession.hpp"
#include "kxSvr.hpp"
#include "KxLogicSys.hpp"
#include "KxLogger.hpp"

#if defined(ASIO_ENABLE_HANDLER_TRACKING)
#define use_awaitable \
	asio::use_awaitable_t(__FILE__, __LINE__, __PRETTY_FUNCTION__)
#endif

constexpr int MAX_SENDQUE = 100;

/* CRC16 implementation acording to CCITT standards */

static const unsigned short crc16tab[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
	0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
	0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
	0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
	0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
	0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
	0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
	0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
	0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
	0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
	0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
	0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
	0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
	0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
	0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
	0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
	0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
	0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
	0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0};

unsigned short crc16_ccitt(const unsigned char *buf, int len)
{
	unsigned short crc = 0;
	for (int counter = 0; counter < len; counter++)
		crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *buf++) & 0x00FF];
	return crc;
}

void KxMsgPacket_Basic::getvecBuffer(std::vector<asio::const_buffer> &vec_buf)
{
	if (m_msgHeader.nTypeFlag == cst_Resp_MsgType)
		vec_buf.push_back(asio::buffer(&m_msgHeader, sizeof(KxMsgRespHeader)));
	else
		vec_buf.push_back(asio::buffer(&m_msgHeader, sizeof(KxMsgHeader)));
	if (getMsgBodyBuf() && getBodyBufLen())
		vec_buf.push_back(asio::buffer(getMsgBodyBuf(), getBodyBufLen()));
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
		KX_LOG_FUNC_(std::format("~KxSession destruct sessionId: 0x{:x} exception: {}", m_nSessionId,exp.what()));
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
			auto msgnodeHeader = m_svrRespToSend_que.front()->getMsgHeader();
			// std::cout << "Resp send OK. MsgId: " << msgnodeHeader.nMsgId << " SessionId: 0x" << std::hex << m_nSessionId << std::dec << std::endl;
			// std::string strLog = "Resp send OK. MsgId: "+std::to_string(msgnodeHeader.nMsgId)+" SessionId: 0x";
			// strLog += std::format("{:X}",m_nSessionId);
			// KX_LOG_FUNC_(strLog);
			KX_LOG_FUNC_(std::format("Resp send OK. MsgId: {:d}  SessionId: 0x{:x}", msgnodeHeader.nMsgId, m_nSessionId));
			m_svrRespToSend_que.pop();
			if (!m_svrRespToSend_que.empty())
			{
				auto msgnode = m_svrRespToSend_que.front();
				lock.unlock();
				std::vector<asio::const_buffer> vec_buf;
				msgnode->getvecBuffer(vec_buf);
				asio::async_write(m_socket, vec_buf,
								  std::bind(&KxDevSession::HandleRespWrited, this, std::placeholders::_1, shared_self));
			}
			else if (!m_svrMsgToSend_que.empty())
			{
				auto msgnode = m_svrMsgToSend_que.front();
				lock.unlock();
				std::vector<asio::const_buffer> vec_buf;
				msgnode->m_sendPacket->getvecBuffer(vec_buf);
				asio::async_write(m_socket, vec_buf,
								  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, shared_self));
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
			auto logicNode = m_svrMsgToSend_que.front();
			m_server->addSvrMsgWaitResp(logicNode);
			m_svrMsgToSend_que.pop();
			if (!m_svrMsgToSend_que.empty())
			{
				auto msgnode = m_svrMsgToSend_que.front();
				lock.unlock();
				std::vector<asio::const_buffer> vec_buf;
				msgnode->m_sendPacket->getvecBuffer(vec_buf);
				asio::async_write(m_socket, vec_buf,
								  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, shared_self));
			}
			else if (!m_svrRespToSend_que.empty())
			{
				auto msgnode = m_svrRespToSend_que.front();
				lock.unlock();
				std::vector<asio::const_buffer> vec_buf;
				msgnode->getvecBuffer(vec_buf);
				asio::async_write(m_socket, vec_buf,
								  std::bind(&KxDevSession::HandleRespWrited, this, std::placeholders::_1, shared_self));
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

	// if (msgHeader_base.nTypeFlag == 0 && msgHeader_base.nMsgId != MSG_DEV_REGISTER)
	// {
	// 	if (pExtData[1] != m_nSessionId)
	// 	{
	// 		brt = false;
	// 	}
	// }
	return brt;
}

std::shared_ptr<KxDevSession> KxDevSession::getDevSession(unsigned int nDevId)
{
	return m_server->getDevSession(nDevId);
}

void KxDevSession::updateDevSessionId(unsigned int nDevId, unsigned int nSessionId)
{
	m_server->updateDevSessionIdMap(nDevId, nSessionId);
}

void KxDevSession::setLastTime(const std::time_t &tm_val)
{
	m_tm_last = tm_val;
}

void KxDevSession::checkTimeOut(const std::time_t &tm_val)
{
	auto tmdiff = tm_val - m_tm_last;
	if (tmdiff > cst_Client_TimeOut_Sec)
	{
		// std::cout << "KxDevSession timeout sessionId: " << std::hex << m_nSessionId << std::dec << std::endl;
		KX_LOG_FUNC_(std::format("KxDevSession timeout sessionId: 0x{:x}", m_nSessionId));
		Close();
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
	lock.unlock();
	std::vector<asio::const_buffer> vec_buf;
	msgnode->m_sendPacket->getvecBuffer(vec_buf);
	asio::async_write(m_socket, vec_buf,
					  std::bind(&KxDevSession::HandleMsgWrited, this, std::placeholders::_1, SharedSelf()));
}
