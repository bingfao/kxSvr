#pragma once

#ifndef KX_MSG_PACKET_HPP_
#define KX_MSG_PACKET_HPP_

#include <asio.hpp>
#include "KxMsgDef.h"

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
			m_nRespCode_u_DevId = pHeadExtData[0];
			if (msgH_base.nTypeFlag != cst_Resp_MsgType)
			{
				m_nSessionId = pHeadExtData[1];
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
	unsigned int getBodyLen() const
	{
		return m_msgHeader.nMsgBodyLen;
	}

	void getvecBuffer(std::vector<asio::const_buffer> &);

	unsigned int getRespCode() const
	{
		return m_nRespCode_u_DevId;
	}
	unsigned int getDevId() const
	{
		return m_nRespCode_u_DevId;
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
    unsigned char * getHeaderBuf() {
		return (unsigned char*)&m_msgHeader;
	}
	unsigned int getHeaderLen() {
		unsigned int nRt = sizeof(KxMsgHeader_Base);
		if(m_msgHeader.nTypeFlag == cst_Resp_MsgType)
		{
			nRt += 2* sizeof(unsigned int);
		}
		else{
			nRt += sizeof(unsigned int);
		}
		return nRt;
	}
	void setSessionId(unsigned int nVal){
		m_nSessionId = nVal;
	}
	unsigned int getSessionId(){
		return m_nSessionId;
	}
	void calculate_crc();
private:
	KxMsgHeader_Base m_msgHeader;
	unsigned int m_nRespCode_u_DevId; // 此处仅为占用内存布局，具体取值，依赖mTypeFlag
	unsigned int m_nSessionId;
	unsigned char *m_pMsgBodyBuf;
	bool m_bNeedDeleteBuf;
};

#pragma pack()


#endif //KX_MSG_PACKET_HPP_