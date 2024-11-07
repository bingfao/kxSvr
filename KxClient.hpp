#pragma once

#ifndef _KX_CLIENT_HPP_
#define _KX_CLIENT_HPP_

#include <iostream>
#include <deque>
#include <list>
#include <asio.hpp>
#include "KxMsgPacket.hpp"
#include "KxMsgDef.h"
#include "aeshelper.hpp"

const int cst_basic_recv_packetbody_buf_len = 2048;

using asio::ip::tcp;

typedef std::deque<std::shared_ptr<KxMsgPacket_Basic>> msgPacket_queue;

class KxClient
{
public:
  KxClient(asio::io_context &io_context,
           const tcp::resolver::results_type &endpoints)
      : io_context_(io_context),
        socket_(io_context),
        m_pReadMsgBodyBuf(nullptr), m_nMsgBodyBufLen(0)
  {
    do_connect(endpoints);
  }
  ~KxClient()
  {
    if (m_pReadMsgBodyBuf)
    {
      delete[] m_pReadMsgBodyBuf;
      m_pReadMsgBodyBuf = nullptr;
    }
  }

  void write(const std::shared_ptr<KxMsgPacket_Basic> &msg)
  {
    asio::post(io_context_,
               [this, msg]()
               {
                 std::unique_lock<std::mutex> lock(m_mutex_tosend);
                 bool write_in_progress = !toSend_msgs_.empty();
                 toSend_msgs_.push_back(msg);
                 if (!write_in_progress)
                 {
                   lock.unlock();
                   do_write();
                 }
               });
  }

  void close()
  {
    asio::post(io_context_, [this]()
               { socket_.close(); });
  }

  unsigned int getSessionId()
  {
    return m_nSessionId;
  }
  void setDevId(unsigned int id)
  {
    m_nDevId = id;
  }
  unsigned int getDevId(){
    return m_nDevId;
  }

  void setAES_Key(const unsigned char *p)
  {
    std::memcpy(m_aes_key, p, AES_IV_BLOCK_SIZE);
  }
  void setAES_Iv(const unsigned char *p)
  {
    std::memcpy(m_aes_iv, p, AES_IV_BLOCK_SIZE);
  }

  bool AES_encryptPacket(const unsigned char *pIn, unsigned int nInBufLen,
                         unsigned char *pOut, unsigned int &nOutBufLen)
  {
    return aes_128_CBC_encrypt(m_aes_key, m_aes_iv, pIn, nInBufLen, pOut, nOutBufLen);
  }

private:
  void do_connect(const tcp::resolver::results_type &endpoints)
  {
    asio::async_connect(socket_, endpoints,
                        [this](std::error_code ec, tcp::endpoint)
                        {
                          if (!ec)
                          {
                            if (!m_pReadMsgBodyBuf)
                            {
                              m_pReadMsgBodyBuf = new unsigned char[cst_basic_recv_packetbody_buf_len];
                            }
                            do_read_header();
                          }
                        });
  }

  void do_read_header()
  {
    asio::async_read(socket_,
                     asio::buffer(read_msg_.getHeaderBuf(), sizeof(KxMsgHeader_Base) + 4),
                     [this](std::error_code ec, std::size_t length)
                     {
                       if (!ec)
                       {
                         bool bRecvLenOk = length == sizeof(KxMsgHeader_Base) + 4;
                         if (bRecvLenOk)
                         {
                           bool bOk(true);
                           if (read_msg_.getMsgHeader().nTypeFlag != cst_Resp_MsgType)
                           {
                             // 需要再读入4个字节
                             auto nRead = asio::read(socket_, asio::buffer(read_msg_.getHeaderBuf() + length, 4));
                             bOk = nRead == 4;
                             length += nRead;
                           }
                           std::cout << "Packet Header:" << std::endl;
                           std::cout << std::hex;
                           unsigned char *pHeaderyBuf = read_msg_.getHeaderBuf();
                           for (int i = 0; i < length; ++i)
                           {
                             // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
                             std::cout << std::setw(2) << std::setfill('0') << (short)pHeaderyBuf[i] << ' ';
                           }
                           std::cout << std::dec << std::endl;
                           if (bOk)
                           {
                             if (read_msg_.getBodyLen())
                               do_read_body();
                             else
                             {
                               onHanleMsg();
                             }
                           }
                           else
                             do_read_header();
                         }
                         else
                         {
                           do_read_header();
                         }
                       }
                       else
                       {
                         socket_.close();
                       }
                     });
  }

  void do_read_body()
  {
    auto nNeedBodyBufLen = read_msg_.getBodyLen();
    if (nNeedBodyBufLen > m_nMsgBodyBufLen)
    {
      m_nMsgBodyBufLen = (nNeedBodyBufLen + cst_basic_recv_packetbody_buf_len - 1) / cst_basic_recv_packetbody_buf_len * cst_basic_recv_packetbody_buf_len;
      if (m_pReadMsgBodyBuf)
      {
        delete[] m_pReadMsgBodyBuf;
        m_pReadMsgBodyBuf = nullptr;
      }
      if (!m_pReadMsgBodyBuf)
      {
        m_pReadMsgBodyBuf = new unsigned char[m_nMsgBodyBufLen];
      }
    }
    asio::async_read(socket_,
                     asio::buffer(m_pReadMsgBodyBuf, nNeedBodyBufLen),
                     [this, nNeedBodyBufLen](std::error_code ec, std::size_t length)
                     {
                       if (!ec)
                       {
                         std::cout << "Packet Body:" << std::endl;
                         unsigned char *pBodyBuf = m_pReadMsgBodyBuf;
                         std::cout << std::hex;
                         for (int i = 0; i < length; ++i)
                         {
                           // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
                           std::cout << std::setw(2) << std::setfill('0') << (short)pBodyBuf[i] << ' ';
                         }
                         std::cout << std::dec << std::endl;

                         // 接收到一个完整包时，进行处理
                         if (length == nNeedBodyBufLen)
                         {
                           onHanleMsg();
                         }

                         do_read_header();
                       }
                       else
                       {
                         socket_.close();
                       }
                     });
  }

  void do_write()
  {
    std::vector<asio::const_buffer> vec_buf;
    std::unique_lock<std::mutex> lock(m_mutex_tosend);
    auto msgnode = toSend_msgs_.front();
    msgnode->getvecBuffer(vec_buf);
    lock.unlock();
    asio::async_write(socket_,
                      vec_buf,
                      [this, msgnode](std::error_code ec, std::size_t /*length*/)
                      {
                        if (!ec)
                        {
                          if (!msgnode->isRespMsg())
                          {
                            std::unique_lock<std::mutex> lock_sended(m_mutex_sended);
                            sended_msgs_.push_back(msgnode);
                            // lock_sended.unlock();
                          }
                          std::unique_lock<std::mutex> lock(m_mutex_tosend);
                          toSend_msgs_.pop_front();
                          // 这里需要注意，不能简单pop掉，需要针对性收到应答处理
                          if (!toSend_msgs_.empty())
                          {
                            lock.unlock();
                            do_write();
                          }
                        }
                        else
                        {
                          socket_.close();
                        }
                      });
  }

  std::shared_ptr<KxMsgPacket_Basic> findPairedMsgSended()
  {
    std::shared_ptr<KxMsgPacket_Basic> ptr = nullptr;
    std::unique_lock<std::mutex> lock_sended(m_mutex_sended);
    for (auto &msg : sended_msgs_)
    {
      if (msg->isPair(read_msg_))
      {
        ptr = msg;
        break;
      }
    }
    return ptr;
  }

  void onHanleMsg()
  {
    auto msg_h = read_msg_.getMsgHeader();
    std::cout << "Handle Recved Msg: " << msg_h.nMsgId << ", msgBodytLen: " << msg_h.nMsgBodyLen << std::endl;
    if (msg_h.nTypeFlag == cst_Resp_MsgType)
    {
      std::cout << "RespCode: " << read_msg_.getRespCode() << std::endl;
    }
    switch (msg_h.nMsgId)
    {
    case 1001:
    {
      if (read_msg_.getRespCode() == cst_nResp_Code_OK)
      {
        auto nBodyLen = read_msg_.getBodyLen();
        if (nBodyLen >= sizeof(unsigned int) + AES_IV_BLOCK_SIZE)
        {
          auto send_msg = findPairedMsgSended();
          if (send_msg)
          {
            m_nSessionId = *(unsigned int *)m_pReadMsgBodyBuf;
            std::memcpy(m_aes_iv, m_pReadMsgBodyBuf + 4, AES_IV_BLOCK_SIZE);

            std::unique_lock<std::mutex> lock_sended(m_mutex_sended);
            sended_msgs_.remove(send_msg);
          }
        }
      }
    }
    break;
    case 9001:
    {
      if (read_msg_.getRespCode() == cst_nResp_Code_OK)
      {
        unsigned char *originMsgBody = nullptr;
        unsigned int nMsgBufLen = 0;
        bool brt = checkAESPacketData(originMsgBody, nMsgBufLen);
        if (brt && originMsgBody && nMsgBufLen)
        {
          auto send_msg = findPairedMsgSended();
          if (send_msg)
          {
            if (nMsgBufLen == sizeof(KxWebSvrRegRespPacketBody_OriginMsg))
            {
              KxWebSvrRegRespPacketBody_OriginMsg *pOrignMsg = (KxWebSvrRegRespPacketBody_OriginMsg *)originMsgBody;

              m_nSessionId = pOrignMsg->nSessionId;
              setAES_Iv(pOrignMsg->szIV);
            }
            std::unique_lock<std::mutex> lock_sended(m_mutex_sended);
            sended_msgs_.remove(send_msg);
          }
          std::cout << "Recved New IV Data: " << std::hex;
          for (int i = 0; i < AES_IV_BLOCK_SIZE; ++i)
          {
            std::cout << std::setw(2) << std::setfill('0') << (short)originMsgBody[i] << ' ';
          }
          std::cout << std::dec << std::endl;

          delete[] originMsgBody;
          originMsgBody = nullptr;
        }
      }
    }
    break;
    case 2001:
    {
      KxMsgHeader_Base msgRespHead_base;
      msgRespHead_base.nMsgId = msg_h.nMsgId;
      msgRespHead_base.nSeqNum = msg_h.nSeqNum;
      msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
      msgRespHead_base.nMsgBodyLen = 0;
      unsigned int nHeaderExtra[2] = {0};
      nHeaderExtra[0] = cst_nResp_Code_OK;
      auto msg = std::make_shared<KxMsgPacket_Basic>(msgRespHead_base, nHeaderExtra, nullptr, false);
      msg->calculate_crc();
      write(msg);
    }
    break;
    default:
      break;
    }
  }

  bool checkAESPacketData(unsigned char *&pOrigin, unsigned int &nOriginDataLen)
  {
    bool brt(false);
    unsigned int nBodyLen = read_msg_.getBodyLen();
    // 先解密
    unsigned int nAesDataLen = nBodyLen - 6;
    unsigned int nCount = nAesDataLen / AES_IV_BLOCK_SIZE;
    unsigned int nLeft = nAesDataLen % AES_IV_BLOCK_SIZE;
    if (nLeft)
      ++nCount;
    nOriginDataLen = nCount * AES_IV_BLOCK_SIZE;
    pOrigin = new unsigned char[nOriginDataLen];
    if (aes_128_CBC_decrypt(m_aes_key, m_aes_iv, m_pReadMsgBodyBuf, nAesDataLen, pOrigin, nOriginDataLen))
    {
      unsigned short nCrc16 = crc16_ccitt((unsigned char *)pOrigin, nOriginDataLen);
      unsigned int *pDataLen = (unsigned int *)(m_pReadMsgBodyBuf + nAesDataLen);
      unsigned short *pCrc = (unsigned short *)(m_pReadMsgBodyBuf + nAesDataLen + 4);
      if (*pCrc == nCrc16 && nOriginDataLen == *pDataLen)
      {
        brt = true;
      }
    }
    return brt;
  }

private:
  asio::io_context &io_context_;
  tcp::socket socket_;
  KxMsgPacket_Basic read_msg_;
  unsigned char *m_pReadMsgBodyBuf;
  unsigned int m_nMsgBodyBufLen;
  unsigned int m_nDevId;
  unsigned int m_nSessionId;
  unsigned char m_aes_key[AES_IV_BLOCK_SIZE];
  unsigned char m_aes_iv[AES_IV_BLOCK_SIZE];
  msgPacket_queue toSend_msgs_;
  std::list<std::shared_ptr<KxMsgPacket_Basic>> sended_msgs_;
  std::mutex m_mutex_tosend;
  std::mutex m_mutex_sended;
};

#endif