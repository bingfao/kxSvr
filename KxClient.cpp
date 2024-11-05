
// #include <cstdlib>
#include <deque>
#include <iostream>
#include <thread>
#include <asio.hpp>
#include "KxMsgPacket.hpp"
#include "KxMsgDef.h"
#include "aeshelper.hpp"

using asio::ip::tcp;

typedef std::deque<std::shared_ptr<KxMsgPacket_Basic>> chat_message_queue;

const unsigned char default_aes_key[] = {0x51, 0x5D, 0x3D, 0x22, 0x97, 0x47, 0xC8, 0xFD, 0x9F, 0x30, 0x41, 0xD0, 0x8C, 0x0A, 0xE9, 0x10};
const unsigned char default_aes_iv[] = {0x13, 0xF1, 0xDA, 0xC8, 0x8B, 0xB6, 0xE2, 0xCD, 0x9B, 0xEA, 0xE0, 0x63, 0x8F, 0x3F, 0x53, 0xAB};

const int cst_basic_recv_packetbody_buf_len = 2048;

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
                 bool write_in_progress = !write_msgs_.empty();
                 write_msgs_.push_back(msg);
                 if (!write_in_progress)
                 {
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
                           if (bOk && read_msg_.getBodyLen())
                             do_read_body();
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
    auto msgnode = write_msgs_.front();
    msgnode->getvecBuffer(vec_buf);
    asio::async_write(socket_,
                      vec_buf,
                      [this](std::error_code ec, std::size_t /*length*/)
                      {
                        if (!ec)
                        {
                          write_msgs_.pop_front();
                          if (!write_msgs_.empty())
                          {
                            do_write();
                          }
                        }
                        else
                        {
                          socket_.close();
                        }
                      });
  }

  void onHanleMsg()
  {
    auto msg_h = read_msg_.getMsgHeader();
    switch (msg_h.nMsgId)
    {
    case 1001:
    {

      if (read_msg_.getRespCode() == cst_nResp_Code_OK)
      {
        auto nBodyLen = read_msg_.getBodyLen();
        if (nBodyLen >= sizeof(unsigned int) + AES_IV_BLOCK_SIZE)
        {
          m_nSessionId = *(unsigned int *)m_pReadMsgBodyBuf;
          std::memcpy(m_aes_iv, m_pReadMsgBodyBuf + 4, AES_IV_BLOCK_SIZE);
        }
      }
    }
    break;
    default:
      break;
    }
  }

private:
  asio::io_context &io_context_;
  tcp::socket socket_;
  KxMsgPacket_Basic read_msg_;
  unsigned char *m_pReadMsgBodyBuf;
  unsigned int m_nMsgBodyBufLen;
  unsigned int m_nSessionId;
  unsigned char m_aes_key[AES_IV_BLOCK_SIZE];
  unsigned char m_aes_iv[AES_IV_BLOCK_SIZE];
  chat_message_queue write_msgs_;
};

const int max_body_length = 255;

int main(int argc, char *argv[])
{
  try
  {
    if (argc != 3)
    {
      std::cerr << "Usage: KxClient <host> <port>\n";
      return 1;
    }

    asio::io_context io_context;

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(argv[1], argv[2]);
    KxClient c(io_context, endpoints);

    std::thread t([&io_context]()
                  { io_context.run(); });
    unsigned short nSeqNum(0);
    unsigned int nHeaderExtra[2] = {0};
    std::cout << "input q to exit" << std::endl;
    while (true)
    {
      auto ch = std::getchar();
      if (ch != EOF)
      {
        KxMsgHeader_Base msg_b;
        msg_b.nTypeFlag = 0;
        msg_b.nSeqNum = nSeqNum++;
        switch (ch)
        {
        case 'q':
        case 'Q':
          break;
        case '1':
        {
          msg_b.nMsgId = 1001;
          msg_b.nMsgBodyLen = sizeof(KxDevRegPacketBody);
          KxDevRegPacketBody tbody;
          nHeaderExtra[0] = 10001;
          auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
          msg->calculate_crc();
          c.write(msg);
        }
        break;
        case '2':
        {
          msg_b.nMsgId = 1002;
          msg_b.nMsgBodyLen = sizeof(KxDevStatusPacketBody_Base);
          KxDevStatusPacketBody_Base tbody;
          nHeaderExtra[0] = 10001;
          nHeaderExtra[1] = c.getSessionId();
          auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
          msg->calculate_crc();
          c.write(msg);
        }
        break;
        case '9':
        {
          msg_b.nMsgId = 9001;
          msg_b.nCryptFlag = 1;
          unsigned char databuf[128] = {0};
          const std::chrono::time_point<std::chrono::system_clock> tp_now =
              std::chrono::system_clock::now();
          const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
          memcpy(databuf, &t_c, sizeof(std::time_t));
          const char szHost[] = "kingxun.site";
          memcpy(databuf + 8, szHost, sizeof(szHost));
          int ndataLen = 8 + sizeof(szHost);
          unsigned char szBodyRegOut[128] = {0};
          unsigned int nOutBufLen = sizeof(szBodyRegOut);
          bool brt = aes_128_CBC_encrypt(default_aes_key, default_aes_iv, databuf, ndataLen, szBodyRegOut, nOutBufLen);
          if (brt)
          {
            msg_b.nMsgBodyLen = nOutBufLen + 6;
            unsigned int *pDataLen = (unsigned int *)(szBodyRegOut + nOutBufLen);
            *pDataLen = ndataLen;
            unsigned short *pCrc16 = (unsigned short *)(szBodyRegOut + nOutBufLen + 4);
            *pCrc16 = crc16_ccitt((unsigned char *)databuf, ndataLen);
            nHeaderExtra[0] = 0;
            nHeaderExtra[1] = 0;
            auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)szBodyRegOut, true);
            msg->calculate_crc();
            c.write(msg);
          }
        }
        break;
        case '4':
          break;
        }
      }
      else
      {
        break;
      }
    }

    c.close();
    t.join();
  }
  catch (std::exception &e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}

// cl /EHsc KxClient.cpp KxMsgPacket.cc aeshelper.cc  /wd4819  /std:c++20 -I D:\workspace\asio\asio\include -D_WIN32_WINNT=0x0601 /Fe:kxclient.exe -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib