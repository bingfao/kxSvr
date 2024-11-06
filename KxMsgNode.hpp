#pragma once

#ifndef KX_MSG_NODE_HPP_
#define KX_MSG_NODE_HPP_

#include <iostream>

#include "KxMsgPacket.hpp"
//#include "KxLogger.hpp"

#define KX_USING_DEV_SESSION

#ifdef KX_USING_DEV_SESSION

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
	// ~KxBussinessLogicNode()
	// {
	// 	KX_LOG_FUNC_("KxBussinessLogicNode Destructor");
	// }

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

#endif // KX_MSG_NODE_HPP_