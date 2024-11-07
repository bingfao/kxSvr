#pragma once

#ifndef _KX_SESSION_HPP_
#define _KX_SESSION_HPP_

#include <asio.hpp>
#include <queue>
#include "KxMsgNode.hpp"
#include "KxMsgDef.h"
#include "KxLogger.hpp"

class KxServer;

class KxMsgLogicNode
{
	// friend class KxDevSession;
	// friend class kxServer;
public:
	KxMsgLogicNode(std::shared_ptr<KxMsgPacket_Basic> msgPacket, std::shared_ptr<KxBussinessLogicNode> logicNode = nullptr)
		: m_sendPacket(msgPacket), m_logicNode(logicNode), m_timestamp(std::time(nullptr))
	{
	}
	~KxMsgLogicNode()
	{
		KX_LOG_FUNC_("KxMsgLogicNode Destructor");
	}

public:
	std::shared_ptr<KxMsgPacket_Basic> m_sendPacket;
	std::shared_ptr<KxBussinessLogicNode> m_logicNode;
	std::time_t m_timestamp;
};

class KxDevSession : public std::enable_shared_from_this<KxDevSession>
{
public:
	KxDevSession(asio::io_context &io_context, KxServer *server);
	~KxDevSession();

	asio::ip::tcp::socket &GetSocket()
	{
		return m_socket;
	}
	unsigned int GetSessionId()
	{
		return m_nSessionId;
	}
	void SetSessionId(unsigned int nSessionId)
	{
		m_nSessionId = nSessionId;
	}
	void Start();
	void onPeerClose();
	void Close();

	void SendRespPacket(const KxMsgHeader_Base &msgHeader, unsigned int nRespCode, unsigned char *pBodyBuf = nullptr, bool bDelBuf = false);
	void SendMsgPacket(const KxMsgHeader_Base &msgHeader, unsigned char *pBodyBuf = nullptr, bool bDelBuf = false, std::shared_ptr<KxBussinessLogicNode> pLogicNode = nullptr);
	std::shared_ptr<KxDevSession> SharedSelf()
	{
		return shared_from_this();
	}
	bool checkMsgHeader(const KxMsgHeader_Base &msgHeader_base, unsigned int *pExtData);
	bool checkAESPacketData(const unsigned char *pBody, unsigned int nBodyLen, unsigned char *&pOrigin, unsigned int &nOriginDataLen);

	// void updateAES_IV(const unsigned char*);
	void RandIVData();
	void setAES_Iv(const unsigned char *);
	void setAES_Key(const unsigned char *);

	void onMsgResp(std::shared_ptr<KxMsgPacket_Basic> resp);
	std::shared_ptr<KxDevSession> getDevSession(unsigned int nDevId);

	void updateDevSessionId(unsigned int nDevId, unsigned int nSessionId);
	unsigned int getDevCount();


	void setLastTime(const std::time_t &);
	std::time_t getLastTime()
	{
		return m_tm_last;
	}
	void checkTimeOut(const std::time_t &tm_val);
	unsigned char *getAESIvData()
	{
		return m_aes_iv;
	}
	void getDevAESKeyData();

	bool AES_encrypt(const unsigned char *pIn, unsigned int nInBufLen,
					 unsigned char *pOut, unsigned int &nOutBufLen);
	bool AES_decrypt(const unsigned char *pData, unsigned int nDataLen,
					 unsigned char *pOut, unsigned int &nOutDataLen);

	void setWebSvr()
	{
		m_bWebSvr = true;
	}

private:
	void HandleMsgWrited(const asio::error_code &error, std::shared_ptr<KxDevSession> shared_self);
	void HandleRespWrited(const asio::error_code &error, std::shared_ptr<KxDevSession> shared_self);
	asio::ip::tcp::socket m_socket;
	unsigned int m_nDevId;
	unsigned int m_nSessionId;
	unsigned char m_dataBuf[MAX_LENGTH];
	KxServer *m_server;
	bool m_b_close;
	std::queue<std::shared_ptr<KxMsgPacket_Basic>> m_svrRespToSend_que; // 这里存放应答包
	std::queue<std::shared_ptr<KxMsgLogicNode>> m_svrMsgToSend_que;
	std::mutex m_send_mutex; // 发送互斥量

	asio::io_context &m_io_context;
	std::time_t m_tm_last;
	unsigned char m_aes_key[AES_IV_BLOCK_SIZE];
	unsigned char m_aes_iv[AES_IV_BLOCK_SIZE];
	bool m_bWebSvr;
};

#endif //_KX_SESSION_HPP_