
// #include <cstdlib>

#include "KxClient.hpp"
#include "kxLog_iostream.h"
#include <fstream>
#include <chrono>
#include <thread>
#include <openssl/evp.h>

using asio::ip::tcp;

using namespace std::chrono_literals;

const unsigned short cst_ushort_1022_packet_len = 2048;

const unsigned char default_aes_key[] = {0x51, 0x5D, 0x3D, 0x22, 0x97, 0x47, 0xC8, 0xFD, 0x9F, 0x30, 0x41, 0xD0, 0x8C, 0x0A, 0xE9, 0x10};
const unsigned char default_aes_iv[] = {0x13, 0xF1, 0xDA, 0xC8, 0x8B, 0xB6, 0xE2, 0xCD, 0x9B, 0xEA, 0xE0, 0x63, 0x8F, 0x3F, 0x53, 0xAB};

const unsigned char dev10001_aes_key[] = {0x3e, 0xb4, 0x2f, 0x14, 0x81, 0xbe, 0x6c, 0x35, 0xed, 0x3f, 0xe9, 0xf4, 0x3d, 0x96, 0x49, 0x2e};
const unsigned char dev10002_aes_key[] = {0xb9, 0xde, 0x35, 0xcf, 0x97, 0x2c, 0x80, 0x4b, 0x0c, 0x4b, 0x90, 0x0f, 0x33, 0xe3, 0x28, 0x48};
const unsigned char dev10009_aes_key[] = {0xfa, 0x91, 0x97, 0xfe, 0x55, 0xd5, 0x34, 0xe9, 0x41, 0x5a, 0x89, 0x6a, 0x84, 0x1f, 0xb5, 0x4f};

// const int max_body_length = 255;

void Kx_MD5(unsigned char *szbuf, int nbufLen, unsigned char *md5_digest,
            int &ndigestLen)
{
  unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
  if (ndigestLen >= md5_digest_len)
  {
    // MD5_Init
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    // MD5_Update
    EVP_DigestUpdate(mdctx, szbuf, nbufLen);
    // MD5_Final
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    ndigestLen = (int)md5_digest_len;
    EVP_MD_CTX_free(mdctx);
  }
}

int main(int argc, char *argv[])
{
  EVP_add_cipher(EVP_aes_128_cbc());
  try
  {
    if (argc != 4)
    {
      std::cerr << "Usage: KxClient <host> <port> <devid>\n";
      return 1;
    }

    asio::io_context io_context;

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(argv[1], argv[2]);

    int nDevId = std::atoi(argv[3]);

    KxClient c(io_context, endpoints);

    std::thread t([&io_context]()
                  { io_context.run(); });
    unsigned short nSeqNum(0);
    unsigned int nHeaderExtra[2] = {0};
    bool bExit = false;
    std::string str_input;
    int nSocP = 64;
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
        c.setDevId(nDevId);
        msg_b.nMsgId = 1001;
        msg_b.nMsgBodyLen = sizeof(KxDevRegPacketBody);
        KxDevRegPacketBody tbody;
        auto nDevId = nHeaderExtra[0] = c.getDevId();
        switch (nDevId)
        {
        case 10001:
          c.setAES_Key(dev10001_aes_key);
          break;
        case 10002:
          c.setAES_Key(dev10002_aes_key);
          break;
        case 10009:
          c.setAES_Key(dev10009_aes_key);
          break;
        }
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

        KxDevStatusPacketBody_Base *pDevStatus = &tbody;
        pDevStatus->nDevType = 1;
        pDevStatus->nProtocolFlag = 1;
        pDevStatus->lngPos = 121.54409;
        pDevStatus->latPos = 31.22114;
        pDevStatus->mileage = 36 * c.getDevId();
        // pDevStatus->bDriving = 1;
        // pDevStatus->speed = 4.8*nDevId;
        pDevStatus->bMiniBatExist = true;
        strcpy_s(pDevStatus->szMiniBatteryId, "EEAD2002024991");
        pDevStatus->miniBatteryStatus.socPercent = 82;
        pDevStatus->miniBatteryStatus.voltage = 1320;
        pDevStatus->seriesCount = 1;
        pDevStatus->batteryExist = true;
        if (nSocP < 80)
          pDevStatus->chargeFlag = 1;
        else
          pDevStatus->chargeFlag = 0;
        strcpy_s(pDevStatus->szBatteryId, "FFAD2002024991");
        pDevStatus->batteryStatus.socPercent = nSocP++;
        pDevStatus->batteryStatus.voltage = 5440;
        pDevStatus->batteryStatus.temp = 3200;

        pDevStatus->batteryStatus.current = 0;

        if (nSeqNum % 2 == 0)
          pDevStatus->Status.lockStatus = 0x0C;
        else
          pDevStatus->Status.lockStatus = 0x0D;
        pDevStatus->Status.lightStatus = 0x05;
        pDevStatus->Status.sensorStatus = 0x06;
        pDevStatus->Status.brakeStatus = 0x33;

        nHeaderExtra[0] = c.getDevId();
        nHeaderExtra[1] = c.getSessionId();
        auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
        msg->calculate_crc();
        c.write(msg);
      }
      else if (str_input == "1004")
      {
        c.setDevId(nDevId);
        msg_b.nMsgId = 1004;
        msg_b.nMsgBodyLen = sizeof(KxDevUsedTrafficPacketBody);
        KxDevUsedTrafficPacketBody tbody;
        tbody.nDevType = 1;
        tbody.nProtocolFlag = 1;
        tbody.nUsedTraffic = 3000;
        nHeaderExtra[0] = c.getDevId();
        nHeaderExtra[1] = c.getSessionId();
        auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)&tbody, true);
        msg->calculate_crc();
        c.write(msg);
      }
      else if (str_input == "4020")
      {
        c.setDevId(0);
        msg_b.nMsgId = 4020;

        std::string strFileData;
        const std::string strFileName = "weather.mp3";
        const std::string strFileUrl = "./weather.mp3";
        // const std::string strFileName = "pekon.pptx";
        // const std::string strFileUrl = "d:/pekon.pptx";
        if (std::ifstream is{strFileUrl, std::ios::binary | std::ios::ate})
        {
          auto size = is.tellg();
          unsigned int nFileLen = size;
          strFileData.assign(size, '\0'); // construct string to stream size
          is.seekg(0);
          if (is.read(&strFileData[0], size))
          {
            // 需要分配一块内存
            const unsigned int nBufLen = sizeof(KxAppDevCtrlFileDeliver_Base) + nFileLen - FILE_DATA_BASE_LEN;
            msg_b.nMsgBodyLen = nBufLen;
            unsigned char *pFileDeliverMsg = new unsigned char[nBufLen];
            if (pFileDeliverMsg)
            {
              KxAppDevCtrlFileDeliver_Base &dev_msg = *(KxAppDevCtrlFileDeliver_Base *)pFileDeliverMsg;
              dev_msg.devtype = 1;
              dev_msg.nDevId = 10009;
              dev_msg.nSysUsrId = 900001;
              dev_msg.svrTime = std::time(nullptr);
              dev_msg.FileType = 1;
              std::strncpy(dev_msg.szFileName, strFileName.c_str(), sizeof(dev_msg.szFileName));
              dev_msg.nFileLen = nFileLen;
              // 计算MD5
              int nMdLen = sizeof(dev_msg.fileMd5);
              Kx_MD5((unsigned char *)strFileData.c_str(), nFileLen,
                     dev_msg.fileMd5, nMdLen);
              // KX_LOG_FUNC_(dev_msg.fileMd5,nMdLen);
              memcpy(dev_msg.szFileData, &strFileData[0], nFileLen);

              nHeaderExtra[0] = c.getDevId();
              nHeaderExtra[1] = c.getSessionId();
              auto msg = std::make_shared<KxMsgPacket_Basic>(msg_b, nHeaderExtra, (unsigned char *)pFileDeliverMsg, true);
              msg->calculate_crc();
              c.write(msg);

              delete[] pFileDeliverMsg;
              pFileDeliverMsg = nullptr;
            }
          }
          is.close();
        }
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

        KxAppDevCtrlOpenLock_OrMsg openlock_msg;
        openlock_msg.nDevId = 10001;
        openlock_msg.devtype = 1;
        openlock_msg.nUsrId = 1;
        openlock_msg.svrTime = t_c;
        openlock_msg.nAlowTime = 1440;
        openlock_msg.nLowestSocP = 20;
        openlock_msg.nFarthestDist = 50000;

        unsigned char *pBodyBuf = (unsigned char *)&openlock_msg;
        std::cout << "Origin Packet Data: " << std::hex;

        // for (int i = 0; i < sizeof(openlock_msg); ++i)
        // {
        //   // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
        //   std::cout << std::setw(2) << std::setfill('0') << (short)pBodyBuf[i] << ' ';
        // }
        KX_LOG_FUNC_(pBodyBuf, sizeof(openlock_msg));
        std::cout << std::dec << std::endl;

        unsigned char szBodyRegOut[128] = {0};
        unsigned int nOutBufLen = sizeof(szBodyRegOut);
        if (c.AES_encryptPacket(pBodyBuf, sizeof(openlock_msg), szBodyRegOut, nOutBufLen))
        {
          std::cout << "aes encrypted Data: " << std::hex;
          // for (int i = 0; i < nOutBufLen; ++i)
          // {
          //   // std::cout<<std::hex<<ste::setw(2)<<std::fill('0')<<pBodyBuf[i];
          //   std::cout << std::setw(2) << std::setfill('0') << (short)szBodyRegOut[i] << ' ';
          // }
          KX_LOG_FUNC_(szBodyRegOut, nOutBufLen);
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

void KxClient::startRecvMsgHandlingThread()
{
  m_b_thdExit = false;
  m_recvMsgHandling_thread = std::thread(&KxClient::thdFun_doHandleRecvedMsg, this);
}

void KxClient::dealOneItem()
{
  if (!reeced_msgs_.empty())
  {
    auto item = reeced_msgs_.front();
    onHanleMsg(item);
    reeced_msgs_.pop_front();
  }
}

void KxClient::thdFun_doHandleRecvedMsg()
{
  for (;;)
  {
    // 判断是否为关闭状态，把所有逻辑执行完后则退出循环
    std::unique_lock<std::mutex> unique_lk(m_mutex_queueRecved);
    while (reeced_msgs_.empty() && !m_b_thdExit)
    {
      m_cond_consume.wait(unique_lk);
    }
    if (m_b_thdExit)
    {
      reeced_msgs_.clear();
      break;
    }
    else
    {
      dealOneItem();
    }
  }
}

void KxClient::AddRecvedMsgToQueue()
{

  auto msg_h = read_msg_.getMsgHeader();
  std::cout << "AddRecvedMsgToQueue : " << msg_h.nMsgId << ", msgBodytLen: " << msg_h.nMsgBodyLen << ", seqNum: " << msg_h.nSeqNum << std::endl;
  if (read_msg_.getBodyLen())
  {
    std::unique_lock<std::mutex> unique_lk(m_mutex_queueRecved);
    reeced_msgs_.emplace_back(std::make_shared<KxMsgPacket_Basic>(read_msg_, m_pReadMsgBodyBuf, true));
  }
  else
  {
    std::unique_lock<std::mutex> unique_lk(m_mutex_queueRecved);
    reeced_msgs_.emplace_back(std::make_shared<KxMsgPacket_Basic>(read_msg_, nullptr, false));
  }
  m_cond_consume.notify_one();
}

void KxClient::onHanleMsg(std::shared_ptr<KxMsgPacket_Basic> msg_)
{
  auto msg_h = msg_->getMsgHeader();
  std::cout << "Handle Recved Msg: " << msg_h.nMsgId << ", msgBodytLen: " << msg_h.nMsgBodyLen << ", seqNum: " << msg_h.nSeqNum << std::endl;
  if (msg_h.nTypeFlag == cst_Resp_MsgType)
  {
    std::cout << "RespCode: " << msg_->getRespCode() << std::endl;
  }
  switch (msg_h.nMsgId)
  {
  case 1001:
  {
    if (msg_->getRespCode() == cst_nResp_Code_OK)
    {
      auto nBodyLen = msg_->getBodyLen();
      if (nBodyLen >= sizeof(unsigned int) + AES_IV_BLOCK_SIZE)
      {
        auto send_msg = findPairedMsgSended(*msg_);
        if (send_msg)
        {
          m_nSessionId = *(unsigned int *)m_pReadMsgBodyBuf;
          setAES_Iv(m_pReadMsgBodyBuf + 4);
          KX_LOG_FUNC_(m_aes_iv, sizeof(m_aes_iv));
          std::unique_lock<std::mutex> lock_sended(m_mutex_sended);
          sended_msgs_.remove(send_msg);
        }
      }
    }
  }
  break;
  case 1022:
  {
    if (msg_->getRespCode() == cst_nResp_Code_OK)
    {
      auto nBodyLen = msg_->getBodyLen();
      if (nBodyLen > sizeof(KxDev_FileData_Msg_Base))
      {
        auto msgData = msg_->getMsgBodyBuf();
        KxDev_FileData_Msg_Base &fileData = *(KxDev_FileData_Msg_Base *)(msgData);
        // 计算crc
        int ncrc_len = nBodyLen - 2;
        unsigned short *pDataCrc = (unsigned short *)(msgData + ncrc_len);
        if (*pDataCrc == crc16_ccitt(msgData, ncrc_len))
        {
          std::string strOutFileName = "./saved_1022_";

          strOutFileName += m_fileNotify_msg.szFileName;
          // strOutFileName += std::to_string(msg_h.nSeqNum);
          // strOutFileName += "_";
          // strOutFileName += std::to_string(fileData.nFileDataPos);
          if (m_fileUpdatePos == fileData.nFileDataPos)
          {
            std::ofstream of_file(strOutFileName, std::ios_base::binary | std::ios_base::out | std::ios_base::app);
            if (of_file)
            {
              of_file.write((const char *)fileData.fileData, fileData.nDataLen);
              of_file.close();
              m_fileUpdatePos += fileData.nDataLen;
              if (fileData.nFileDataPos + fileData.nDataLen == m_fileNotify_msg.nFileLen)
              {
                // 发送 1020报文
                // KxDevFileRecvOK_Msg recv_msg;
                // recv_msg.devtype = 1;
                // recv_msg.recvFlag = 1;
                // recv_msg.FileType = m_fileNotify_msg.FileType;
                // std::strncpy(recv_msg.szFileName, m_fileNotify_msg.szFileName, sizeof(recv_msg.szFileName));
                // recv_msg.nFileLen = m_fileNotify_msg.nFileLen;
                // std::memcpy(recv_msg.fileMd5, m_fileNotify_msg.fileMd5, sizeof(recv_msg.fileMd5));
                // const std::time_t t_c = std::time(nullptr);
                // auto tm_val = std::localtime(&t_c);
                // recv_msg.tmYear = tm_val->tm_year + 1900;
                // recv_msg.tmMonth = tm_val->tm_mon + 1;
                // recv_msg.tmDay = tm_val->tm_mday;
                // recv_msg.tmHour = tm_val->tm_hour;
                // recv_msg.tmMin = tm_val->tm_min;
                // recv_msg.tmSec = tm_val->tm_sec;

                // KxMsgHeader_Base msgHead_base;
                // msgHead_base.nMsgId = MSG_DEV_FILE_RECV_OK;
                // msgHead_base.nSeqNum = msg_h.nSeqNum;
                // msgHead_base.nMsgBodyLen = sizeof(recv_msg);
                // unsigned int nHeaderExtra[2] = {0};
                // nHeaderExtra[0] = getDevId();
                // nHeaderExtra[1] = getSessionId();
                // unsigned char *pMsgData = (unsigned char *)&recv_msg;
                // auto msg = std::make_shared<KxMsgPacket_Basic>(msgHead_base, nHeaderExtra, pMsgData, false);
                // msg->calculate_crc();
                // write(msg);
              }
              else
              {
                // 继续发送1022获取更多
                KxDevGet_FileData_Msg getFile_msg;
                getFile_msg.FileType = m_fileNotify_msg.FileType;
                getFile_msg.nDevType = 1;
                getFile_msg.nFileDataPos = m_fileUpdatePos;

                getFile_msg.nDataLen = std::min(m_fileNotify_msg.nFileLen - m_fileUpdatePos, (unsigned int)cst_ushort_1022_packet_len);
                std::strncpy(getFile_msg.szFileName, m_fileNotify_msg.szFileName, sizeof(getFile_msg.szFileName));
                std::memcpy(getFile_msg.fileURL_KEY, m_fileNotify_msg.fileURL_KEY, sizeof(m_fileNotify_msg.fileURL_KEY));

                KxMsgHeader_Base msgHead_base;
                msgHead_base.nMsgId = MSG_DEV_GET_FILE_DATA;
                msgHead_base.nSeqNum = msg_h.nSeqNum + 1;
                msgHead_base.nMsgBodyLen = sizeof(getFile_msg);
                unsigned int nHeaderExtra[2] = {0};
                nHeaderExtra[0] = getDevId();
                nHeaderExtra[1] = getSessionId();
                unsigned char *pFileData = (unsigned char *)&getFile_msg;
                auto msg = std::make_shared<KxMsgPacket_Basic>(msgHead_base, nHeaderExtra, pFileData, false);
                msg->calculate_crc();
                std::this_thread::sleep_for(20ms);
                write(msg);
              }
            }
          }
        }
      }
    }
  }
  break;
  case 9001:
  {
    if (msg_->getRespCode() == cst_nResp_Code_OK)
    {
      unsigned char *originMsgBody = nullptr;
      unsigned int nMsgBufLen = 0;
      bool brt = checkAESPacketData(originMsgBody, nMsgBufLen);
      if (brt && originMsgBody && nMsgBufLen)
      {
        auto send_msg = findPairedMsgSended(*msg_);
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
  case 2020:
  {
    // 记录下文件头信息
    auto nBodyLen = msg_->getBodyLen();
    if (nBodyLen)
    {
      unsigned char *pMsgBody = msg_->getMsgBodyBuf();
      // 是AES后的数据，需要解密
      unsigned char szOut[5120] = {0};
      unsigned int nOutDataLen = sizeof(szOut);
      int nMsgDataLen = nBodyLen - 6;
      if (AES_decryptPacket(pMsgBody, nMsgDataLen, szOut, nOutDataLen))
      {
        // KX_LOG_FUNC_(pMsgBody, nMsgDataLen);
        // KX_LOG_FUNC_(pMsgBody, std::min(256U,nMsgDataLen));
        // KX_LOG_FUNC_(szOut, nOutDataLen);
        // KX_LOG_FUNC_(szOut, std::min(256U,nOutDataLen));
        if (0)
        {
          unsigned int *pnDataLen = (unsigned int *)(pMsgBody + nMsgDataLen);
          unsigned short *pMsgCrc = (unsigned short *)(pnDataLen + 1);
          unsigned short nMsgCRC = crc16_ccitt(szOut, nOutDataLen);
          if (nOutDataLen == *pnDataLen && nMsgCRC == *pMsgCrc)
          {
            if (nOutDataLen > sizeof(KxDevCtrlFileDeliverHeader_OrMsg_Base))
            {
              memcpy(&m_recving_FileHeader, szOut, sizeof(KxDevCtrlFileDeliverHeader_OrMsg_Base));
              KxDeliverFileDataItem dataitem;
              dataitem.nDataLen = nOutDataLen - sizeof(KxDevCtrlFileDeliverHeader_OrMsg_Base) + FILE_DATA_BASE_LEN;
              dataitem.nDataPos = 0;
              dataitem.strData.assign(dataitem.nDataLen, '\0');
              memcpy(&dataitem.strData[0], szOut + sizeof(KxDevCtrlFileDeliverHeader_OrMsg_Base) - FILE_DATA_BASE_LEN, dataitem.nDataLen);
              m_vec_recving_FileData.push_back(std::move(dataitem));
            }
          }
        }
      }
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
  }
  break;
  case 2021:
  {
    // 记录每一段数据信息，全部完成后校验MD5，校验通过后，生成文件
    if (0)
    {
      auto nBodyLen = msg_->getBodyLen();
      if (nBodyLen >= sizeof(KxDevCtrlFileDeliverFileData_Base))
      {
        auto pMsgBody = msg_->getMsgBodyBuf();
        KxDevCtrlFileDeliverFileData_Base *pFileData = (KxDevCtrlFileDeliverFileData_Base *)pMsgBody;
        if (strcmp(pFileData->szFileName, m_recving_FileHeader.szFileName) == 0 && nBodyLen - sizeof(KxDevCtrlFileDeliverFileData_Base) + 1 == pFileData->nDataLen)
        {
          KxDeliverFileDataItem dataitem;
          dataitem.nDataLen = pFileData->nDataLen;
          dataitem.nDataPos = pFileData->nFileDataPos;
          dataitem.strData.assign(dataitem.nDataLen, '\0');
          memcpy(&dataitem.strData[0], pFileData->fileData, pFileData->nDataLen);
          m_vec_recving_FileData.push_back(std::move(dataitem));
          if (pFileData->nFileDataPos + pFileData->nDataLen == m_recving_FileHeader.nFileLen)
          {
            // check to save
            std::string strFileContent;
            for (auto item : m_vec_recving_FileData)
            {
              strFileContent.append(item.strData);
            }
            // 计算MD5
            std::string strOutFileName = "./saved_";
            strOutFileName += m_recving_FileHeader.szFileName;
            std::ofstream of_file(strOutFileName, std::ios_base::binary | std::ios_base::out);
            if (of_file)
            {
              of_file.write(&strFileContent[0], m_recving_FileHeader.nFileLen);
              of_file.close();
            }
            m_vec_recving_FileData.clear();
          }
        }
      }
    }
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
  case 2022:
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

    auto nBodyLen = msg_->getBodyLen();
    if (nBodyLen)
    {
      unsigned char *pMsgBody = msg_->getMsgBodyBuf();
      // 是AES后的数据，需要解密
      unsigned char szOut[256] = {0};
      unsigned int nOutDataLen = sizeof(szOut);
      int nMsgDataLen = nBodyLen - 6;
      if (AES_decryptPacket(pMsgBody, nMsgDataLen, szOut, nOutDataLen))
      {
        unsigned int *pnDataLen = (unsigned int *)(pMsgBody + nMsgDataLen);
        unsigned short *pMsgCrc = (unsigned short *)(pnDataLen + 1);
        unsigned short nMsgCRC = crc16_ccitt(szOut, nOutDataLen);
        if (nOutDataLen == *pnDataLen && nMsgCRC == *pMsgCrc)
        {
          if (nOutDataLen == sizeof(KxDevFileUpdateNotify_OrMsg))
          {
            KxDevFileUpdateNotify_OrMsg &notify_msg = *(KxDevFileUpdateNotify_OrMsg *)szOut;
            std::memcpy(&m_fileNotify_msg, szOut, sizeof(KxDevFileUpdateNotify_OrMsg));

            KxDevGet_FileData_Msg getFile_msg;
            getFile_msg.FileType = notify_msg.FileType;
            getFile_msg.nDevType = 1;
            getFile_msg.nFileDataPos = m_fileUpdatePos = 0;
            getFile_msg.nDataLen = std::min(notify_msg.nFileLen, (unsigned int)cst_ushort_1022_packet_len);
            std::strncpy(getFile_msg.szFileName, notify_msg.szFileName, sizeof(getFile_msg.szFileName));
            std::memcpy(getFile_msg.fileURL_KEY, notify_msg.fileURL_KEY, sizeof(notify_msg.fileURL_KEY));

            KxMsgHeader_Base msgHead_base;
            msgHead_base.nMsgId = MSG_DEV_GET_FILE_DATA;
            msgHead_base.nSeqNum = msg_h.nSeqNum;
            msgHead_base.nMsgBodyLen = sizeof(getFile_msg);
            unsigned int nHeaderExtra[2] = {0};
            nHeaderExtra[0] = getDevId();
            nHeaderExtra[1] = getSessionId();
            unsigned char *pFileData = (unsigned char *)&getFile_msg;
            auto msg = std::make_shared<KxMsgPacket_Basic>(msgHead_base, nHeaderExtra, pFileData, false);
            msg->calculate_crc();
            std::this_thread::sleep_for(20ms);
            write(msg);
          }
        }
      }
    }
  }
  break;
  default:
    break;
  }
}

// cl /EHsc KxClient.cpp KxMsgPacket.cc aeshelper.cc  /wd4819  /std:c++20 -I D:\workspace\asio\asio\include -D_WIN32_WINNT=0x0601 /Fe:kxclient.exe -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib