
// #include <cstdlib>

#include <thread>
#include "KxClient.hpp"

using asio::ip::tcp;

const unsigned char default_aes_key[] = {0x51, 0x5D, 0x3D, 0x22, 0x97, 0x47, 0xC8, 0xFD, 0x9F, 0x30, 0x41, 0xD0, 0x8C, 0x0A, 0xE9, 0x10};
const unsigned char default_aes_iv[] = {0x13, 0xF1, 0xDA, 0xC8, 0x8B, 0xB6, 0xE2, 0xCD, 0x9B, 0xEA, 0xE0, 0x63, 0x8F, 0x3F, 0x53, 0xAB};

// const int max_body_length = 255;

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
    bool bExit = false;
    std::string str_input;
    while (true)
    {
      std::cout << "input q to exit" << std::endl;
      std::getline(std::cin, str_input);
      KxMsgHeader_Base msg_b;
      msg_b.nTypeFlag = 0;
      msg_b.nSeqNum = nSeqNum++;
      if (str_input == "q" || str_input == "Q" || str_input == "quit" || str_input == "Quit")
      {
        break;
      }
      else if (str_input == "1" || str_input == "1001")
      {
        c.setDevId(10001);
        msg_b.nMsgId = 1001;
        msg_b.nMsgBodyLen = sizeof(KxDevRegPacketBody);
        KxDevRegPacketBody tbody;
        nHeaderExtra[0] = c.getDevId();
        nHeaderExtra[1] = 0;
        auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
        msg->calculate_crc();
        c.write(msg);
      }
      else if (str_input == "2" || str_input == "1002")
      {
        msg_b.nMsgId = 1002;
        msg_b.nMsgBodyLen = sizeof(KxDevStatusPacketBody_Base);
        KxDevStatusPacketBody_Base tbody;
        nHeaderExtra[0] = c.getDevId();
        nHeaderExtra[1] = c.getSessionId();
        auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
        msg->calculate_crc();
        c.write(msg);
      }
      else if (str_input == "9" || str_input == "9001")
      {
        c.setDevId(0);
        msg_b.nMsgId = 9001;
        msg_b.nCryptFlag = 1;
        unsigned char databuf[128] = {0};
        const std::time_t t_c = std::time(nullptr);
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
          nHeaderExtra[0] = c.getDevId();
          nHeaderExtra[1] = 0;
          auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)szBodyRegOut, true);
          msg->calculate_crc();
          c.setAES_Key(default_aes_key);
          c.setAES_Iv(default_aes_iv);
          c.write(msg);
        }
      }
      else if (str_input == "9002")
      {
        msg_b.nMsgId = 9002;
        msg_b.nCryptFlag = 0;
        KxWebSvrHeartBeat heartbeat;
        const std::time_t t_c = std::time(nullptr);
        heartbeat.curTime = t_c;
        const char szHost[] = "kingxun.site";
        memcpy(heartbeat.szHost, szHost, sizeof(szHost));
        msg_b.nMsgBodyLen = sizeof(KxWebSvrHeartBeat);
        nHeaderExtra[0] = c.getDevId();
        nHeaderExtra[1] = c.getSessionId();
        auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&heartbeat, true);
        msg->calculate_crc();
        c.write(msg);
      }
      else if (str_input == "4" || str_input == "4001")
      {
        const std::time_t t_c = std::time(nullptr);
        msg_b.nMsgId = 4001;
        msg_b.nCryptFlag = 1;

        KxAppDevCtrlOpenLock_OriginMsg openlock_msg;
        openlock_msg.nDevId = 10001;
        openlock_msg.devtype = 1;
        openlock_msg.nUsrId = 1;
        openlock_msg.svrTime = t_c;
        openlock_msg.nAlowTime = 1440;
        openlock_msg.nLowestSocP = 20;
        openlock_msg.nFarthestDist = 50000;

        unsigned char *pBodyBuf = (unsigned char *)&openlock_msg;
        std::cout << "Origin Packet Data: " << std::hex;
        for (int i = 0; i < sizeof(openlock_msg); ++i)
        {
          // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
          std::cout << std::setw(2) << std::setfill('0') << (short)pBodyBuf[i] << ' ';
        }
        std::cout << std::dec << std::endl;

        unsigned char szBodyRegOut[128] = {0};
        unsigned int nOutBufLen = sizeof(szBodyRegOut);
        if (c.AES_encryptPacket(pBodyBuf, sizeof(openlock_msg), szBodyRegOut, nOutBufLen))
        {
          std::cout << "aes encrypted Data: " << std::hex;
          for (int i = 0; i < nOutBufLen; ++i)
          {
            // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
            std::cout << std::setw(2) << std::setfill('0') << (short)szBodyRegOut[i] << ' ';
          }
          std::cout << std::dec << std::endl;

          msg_b.nMsgBodyLen = nOutBufLen + 6;
          unsigned int *pDataLen = (unsigned int *)(szBodyRegOut + nOutBufLen);
          *pDataLen = sizeof(openlock_msg);
          unsigned short *pCrc16 = (unsigned short *)(szBodyRegOut + nOutBufLen + 4);
          *pCrc16 = crc16_ccitt((unsigned char *)pBodyBuf, sizeof(openlock_msg));
          nHeaderExtra[0] = c.getDevId();
          nHeaderExtra[1] = c.getSessionId();
          auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)szBodyRegOut, true);
          msg->calculate_crc();
          c.write(msg);
        }
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