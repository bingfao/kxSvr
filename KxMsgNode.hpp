#pragma once

#include <iostream>
#include <asio.hpp>
#include "KxMsgDef.h"


#define KX_USING_DEV_SESSION

#ifdef KX_USING_DEV_SESSION

unsigned short crc16_ccitt(const unsigned char *buf, int len);


#pragma pack(1)

class KxMsgPacket_Basic
{
public:
	KxMsgPacket_Basic()
		: m_pMsgBodyBuf(nullptr), m_bNeedDeleteBuf(false)
	{
	}
	KxMsgPacket_Basic(const KxMsgHeader_Base &msgH_base, unsigned int *pHeadExtData, unsigned char *pBody, bool bNeedDelBuf)
	{
		KxMsgPacket_Basic();
		std::memcpy(&m_msgHeader, &msgH_base, sizeof(KxMsgHeader_Base));
		if (pHeadExtData)
		{
			nRespCode_u_DevId = pHeadExtData[0];
			if (msgH_base.nTypeFlag != cst_Resp_MsgType)
			{
				nSessionId = pHeadExtData[1];
			}
		}
		m_bNeedDeleteBuf = bNeedDelBuf;
		if (m_bNeedDeleteBuf)
		{
			m_pMsgBodyBuf = new unsigned char[m_msgHeader.nMsgBodyLen];
			if (pBody)
				memcpy(m_pMsgBodyBuf, pBody, m_msgHeader.nMsgBodyLen);
		}
		else
		{
			if (pBody)
				m_pMsgBodyBuf = pBody;
		}
	}
	~KxMsgPacket_Basic()
	{
		if (m_bNeedDeleteBuf && m_pMsgBodyBuf)
		{
			delete[] m_pMsgBodyBuf;
			m_pMsgBodyBuf = nullptr;
		}
	}
	const KxMsgHeader_Base &getMsgHeader() const
	{
		return m_msgHeader;
	}
	// KxMsgHeader_Base   getMsgHeader_() const
	// {
	// 	return m_msgHeader;
	// }
	void SetBodyBuf(unsigned char *pBuf, bool bNeedDelete)
	{
		m_pMsgBodyBuf = pBuf;
		m_bNeedDeleteBuf = bNeedDelete;
	}
	unsigned char *getMsgBodyBuf() const
	{
		return m_pMsgBodyBuf;
	}
	unsigned int getBodyBufLen() const
	{
		return m_msgHeader.nMsgBodyLen;
	}

	void getvecBuffer(std::vector<asio::const_buffer> &);

	unsigned int getRespCode() const
	{
		return nRespCode_u_DevId;
	}
	unsigned int getDevId() const
	{
		return nRespCode_u_DevId;
	}
	bool isPair(const KxMsgPacket_Basic &msg)
	{
		bool brt(false);
		auto msg_h = msg.getMsgHeader();
		if (m_msgHeader.nSeqNum == msg_h.nSeqNum && m_msgHeader.nMsgId == msg_h.nMsgId)
		{
			if (m_msgHeader.nTypeFlag == 0 && msg_h.nTypeFlag == cst_Resp_MsgType)
			{
				brt = true;
			}
		}
		return brt;
	}

protected:
	KxMsgHeader_Base m_msgHeader;
	unsigned int nRespCode_u_DevId; // 此处仅为占用内存布局，具体取值，依赖mTypeFlag
	unsigned int nSessionId;
	unsigned char *m_pMsgBodyBuf;
	bool m_bNeedDeleteBuf;
};

#pragma pack()

class KxDevSession;

class KxBussinessLogicNode
{
	friend class KxBusinessLogicMgr;
	friend class KxDevSession;
	friend class KxServer;
public:
	KxBussinessLogicNode(std::shared_ptr<KxDevSession> session, std::shared_ptr<KxMsgPacket_Basic> recvPacket)
		: m_session(session), m_recvedPacket(recvPacket)
	{
	}

private:
	std::shared_ptr<KxDevSession> m_session;
	std::shared_ptr<KxMsgPacket_Basic> m_recvedPacket;
};

#else

class KxSession;

class KxMsgNode
{
public:
	KxMsgNode(short max_len) : _total_len(max_len), _cur_len(0)
	{
		_data = new char[_total_len + 1]();
		_data[_total_len] = '\0';
	}

	~KxMsgNode()
	{
		std::cout << "destruct KxMsgNode" << std::endl;
		delete[] _data;
	}

	void Clear()
	{
		::memset(_data, 0, _total_len);
		_cur_len = 0;
	}

	short _cur_len;
	short _total_len;
	char *_data;
};

class RecvNode : public KxMsgNode
{
	friend class KxBusinessLogicMgr;

public:
	RecvNode(short max_len, short msg_id)
		: KxMsgNode(max_len),
		  _msg_id(msg_id)
	{
	}

private:
	short _msg_id;
};

class SendNode : public KxMsgNode
{
	friend class KxBusinessLogicMgr;

public:
	SendNode(const char *msg, short max_len, short msg_id)
		: KxMsgNode(max_len + HEAD_TOTAL_LEN), _msg_id(msg_id)
	{
		// // 先发送id, 转为网络字节序
		// short msg_id_host = asio::detail::socket_ops::host_to_network_short(msg_id);
		// memcpy(_data, &msg_id_host, HEAD_ID_LEN);
		// // 转为网络字节序
		// short max_len_host = asio::detail::socket_ops::host_to_network_short(max_len);
		// memcpy(_data + HEAD_ID_LEN, &max_len_host, HEAD_DATA_LEN);
		// memcpy(_data + HEAD_ID_LEN + HEAD_DATA_LEN, msg, max_len);
	}

private:
	short _msg_id;
};

class KxLogicNode
{
	friend class KxBusinessLogicMgr;

public:
	KxLogicNode(std::shared_ptr<KxSession>, std::shared_ptr<RecvNode>);

private:
	std::shared_ptr<KxSession> _session;
	std::shared_ptr<RecvNode> _recvnode;
};

#endif // KX_USING_DEV_SESSION
