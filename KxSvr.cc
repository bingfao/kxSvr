#include "kxSvr.hpp"
#include <mutex>
#include <iostream>
#include <openssl/evp.h>

#include "KxSession.hpp"
#include "KxAsioServicePool.hpp"
#include "KxLogger.hpp"

const int cst_nSessionBase = 0xFD000000;

Kx_Logger g_kx_log("./log", "svr_Log");

void KX_LOG_FUNC_(const char *szLog)
{
    g_kx_log.LogInfo(szLog);
}

void KX_LOG_FUNC_(const std::string &strLog)
{
    KX_LOG_FUNC_(strLog.c_str());
}

void KX_LOG_FUNC_(unsigned char *pBuf, int nBufLen)
{
    std::stringstream ss;
    for (int i = 0; i < nBufLen; ++i)
    {
        ss << std::setw(2) << std::setfill('0') << std::hex << (short)pBuf[i] << ' ';
    }
    KX_LOG_FUNC_(ss.str());
}

KxServer::KxServer(asio::io_context &io_context, short port)
    : m_io_context(io_context), m_nPort(port), m_acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)), m_nsessionCount(0)
{
    // std::cout << "Server start success, listen on port : " << m_nPort << std::endl;
    std::string strlog = "Server start success, listen on port : " + std::to_string(m_nPort);
    m_startTime = std::time(nullptr);
    KX_LOG_FUNC_(strlog);
    StartAccept();
    StartCheckTimeOutSessions();
}

KxServer::~KxServer()
{
    // std::cout << "Server destruct on listen port : " << std::dec << m_nPort << std::endl;
    std::string strlog = "Server destruct on listen port : " + std::to_string(m_nPort);
    KX_LOG_FUNC_(strlog);
}

void KxServer::stop()
{
    // std::cout << "Server stop." << std::endl;
    KX_LOG_FUNC_("Server stop.");
    std::unique_lock<std::mutex> svrlst_lock(m_svrMsgList_mutex);
    m_svrMsgWaitResp_list.clear();
    svrlst_lock.unlock();
    std::lock_guard<std::mutex> lock(m_mutex_map);
    for (const auto &[key, session] : m_sessionsMap)
    {
        session->Close();
    }
    m_sessionsMap.clear();
}

unsigned int KxServer::GetNewSessionId()
{
    return cst_nSessionBase + m_nsessionCount;
}

bool KxServer::getDevSessionId(unsigned int nDevId, unsigned int &nSessionId)
{
    bool brt(false);
    if (m_devIdSession_Map.find(nDevId) != m_devIdSession_Map.end())
    {
        nSessionId = m_devIdSession_Map[nDevId];
    }
    return brt;
}

void KxServer::updateDevSessionIdMap(unsigned int nDevId, unsigned int nSessionId)
{
    m_devIdSession_Map[nDevId] = nSessionId;
}

std::shared_ptr<KxDevSession> KxServer::getDevSession(unsigned int nDevId)
{
    std::shared_ptr<KxDevSession> ptr = nullptr;
    if (m_devIdSession_Map.find(nDevId) != m_devIdSession_Map.end())
    {
        auto nSessionId = m_devIdSession_Map[nDevId];
        std::lock_guard<std::mutex> lock(m_mutex_map);
        if (m_sessionsMap.find(nSessionId) != m_sessionsMap.end())
        {
            ptr = m_sessionsMap[nSessionId];
        }
    }

    return ptr;
}

void KxServer::addSvrMsgWaitResp(std::shared_ptr<KxMsgLogicNode> logicNode)
{
    std::unique_lock<std::mutex> svrlst_lock(m_svrMsgList_mutex);
    m_svrMsgWaitResp_list.push_back(logicNode);
    svrlst_lock.unlock();
}

void KxServer::onMsgResp(std::shared_ptr<KxMsgPacket_Basic> resp)
{
    std::unique_lock<std::mutex> svrlst_lock(m_svrMsgList_mutex);
    for (auto msgNode : m_svrMsgWaitResp_list)
    {
        if (msgNode->m_sendPacket->isPair(*resp))
        {
            if (msgNode->m_logicNode)
            {
                // 基于resp
                auto msgPacket = msgNode->m_logicNode->m_recvedPacket;
                if (msgPacket)
                {
                    KxMsgHeader_Base msgRespHead_base;
                    auto msgHeader = msgPacket->getMsgHeader();
                    msgRespHead_base.nMsgId = msgHeader.nMsgId;
                    msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
                    msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
                    msgRespHead_base.nMsgBodyLen = 0;
                    // msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
                    auto session = msgNode->m_logicNode->m_session;
                    if (session)
                        session->SendRespPacket(msgRespHead_base, resp->getRespCode(), nullptr, false);
                }
            }
            break;
        }
    }
}

void KxServer::HandleAccept(std::shared_ptr<KxDevSession> new_session, const asio::error_code &error)
{
    if (!error)
    {
        new_session->Start();
        ++m_nsessionCount;
        //_sessions.insert(make_pair(new_session->GetUuid(), new_session));
        auto nSessionId = GetNewSessionId();
        new_session->SetSessionId(nSessionId);
        std::lock_guard<std::mutex> lock(m_mutex_map);
        m_sessionsMap.insert(make_pair(nSessionId, new_session));
    }
    else
    {
        KX_LOG_FUNC_("session accept failed, error is " + error.message());
        // std::cout << "session accept failed, error is " << error.message() << std::endl;
    }

    StartAccept();
}

void KxServer::StartAccept()
{
    auto &io_context = KxAsioIOServicePool::GetInstance().GetIOService();
    std::shared_ptr<KxDevSession> new_session = std::make_shared<KxDevSession>(io_context, this);
    m_acceptor.async_accept(new_session->GetSocket(), std::bind(&KxServer::HandleAccept, this, new_session, std::placeholders::_1));
}

void KxServer::StartCheckTimeOutSessions()
{
    static asio::steady_timer t(m_io_context, asio::chrono::minutes(1));
    t.async_wait(std::bind(&KxServer::CheckTimeOutSessions, this,
                           asio::placeholders::error, &t));
    // std::cout << "StartCheckTimeOutSessions" << std::endl;
}

void KxServer::CheckTimeOutSvrMsgWaitItem(const std::time_t &tm_now)
{
    std::unique_lock<std::mutex> svrlst_lock(m_svrMsgList_mutex);
    for (auto msgNode : m_svrMsgWaitResp_list)
    {
        if (tm_now - msgNode->m_timestamp > cst_Svr_Wait_DevMsgResp_Sec)
        {
            // 回复超时
            auto logicNode = msgNode->m_logicNode;
            if (logicNode)
            {
                auto msgPacket = logicNode->m_recvedPacket;
                if (msgPacket)
                {
                    KxMsgHeader_Base msgRespHead_base;
                    auto msgHeader = msgPacket->getMsgHeader();
                    msgRespHead_base.nMsgId = msgHeader.nMsgId;
                    msgRespHead_base.nSeqNum = msgHeader.nSeqNum;
                    msgRespHead_base.nTypeFlag = cst_Resp_MsgType;
                    msgRespHead_base.nMsgBodyLen = 0;
                    // msgRespHead_base.nCrc16 = crc16_ccitt((unsigned char *)&msgRespHead_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
                    auto session = logicNode->m_session;
                    if (session)
                        session->SendRespPacket(msgRespHead_base, cst_nResp_Code_SEND_DEV_ERR, nullptr, false);
                }
            }
        }
    }
    m_svrMsgWaitResp_list.remove_if([&tm_now](std::shared_ptr<KxMsgLogicNode> item)
                                    { return tm_now - item->m_timestamp >= cst_Svr_Wait_DevMsgResp_Sec; });
}

void KxServer::CheckTimeOutSessions(const std::error_code & /*e*/,
                                    asio::steady_timer *t)
{
    t->expires_at(t->expiry() + asio::chrono::minutes(1));
    t->async_wait(std::bind(&KxServer::CheckTimeOutSessions, this,
                            asio::placeholders::error, t));
    // 定期检查timeout的session，close掉
    // std::cout << "CheckTimeOutSessions" << std::endl;
    // KX_LOG_FUNC_("CheckTimeOutSessions");
    // const std::chrono::time_point<std::chrono::system_clock> tp_now =
    //     std::chrono::system_clock::now();
    // const std::time_t t_c =  std::chrono::system_clock::to_time_t(tp_now);
    const std::time_t t_c = std::time(nullptr);
    auto tm_now = std::localtime(&t_c);
    if (tm_now->tm_hour == 0 && tm_now->tm_min < 5)
    {
        g_kx_log.OnCheckDayChanged(tm_now->tm_mday);
    }
    CheckTimeOutSvrMsgWaitItem(t_c);
    static int nTimerCount = 0;
    if (++nTimerCount == 5)
    {
        std::lock_guard<std::mutex> lock(m_mutex_map);
        for (const auto &[key, session] : m_sessionsMap)
        {
            session->checkTimeOut(t_c);
        }
        nTimerCount = 0;
    }
}

void KxServer::ClearSession(unsigned int nSessionId)
{
    if (m_sessionsMap.contains(nSessionId))
    {
        auto session = m_sessionsMap[nSessionId];
        std::unique_lock<std::mutex> svrlst_lock(m_svrMsgList_mutex);
        m_svrMsgWaitResp_list.remove_if([&session](std::shared_ptr<KxMsgLogicNode> item)
                                        { 
                                            bool b(false);
                                            if(item->m_logicNode){
                                                b = item->m_logicNode->m_session == session; 
                                            }
                                            return b;
                                            });
        std::lock_guard<std::mutex> lock(m_mutex_map);
        m_sessionsMap.erase(nSessionId);
    }
}

// bool bstop = false;
// std::condition_variable cond_quit;
// std::mutex mutex_quit;

int main(int argc, const char *argv[])
{
    try
    {
        auto &pool = KxAsioIOServicePool::GetInstance();
        asio::io_context io_context;
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        EVP_add_cipher(EVP_aes_128_cbc());

#ifdef USING_DIFFERENT_PORT
        KxServer s(io_context, 10085);
#else
        KxServer s(io_context, 10086);
#endif
        signals.async_wait([&io_context, &pool, &s](auto, int signal_number)
                           {
            //std::cout<<" Signal occurred: "<<signal_number<<std::endl;

			io_context.stop();
            s.stop();
			pool.Stop(); 
            KX_LOG_FUNC_("svr is closing. Signal occurred: "+ std::to_string(signal_number));
            g_kx_log.close(); });

        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    std::cout << "svr is exit!" << std::endl;
}

// 175.24.207.98

//  g++ ./*.cc -o ./kxsvr -std=c++20 -I../../asio/asio/include
//  g++ ./*.cc -o ./kxsvr -std=c++20 -I../../asio/asio/include -DUSING_PQ_DB_ -lpqxx -lpq -lcrypto

//  cl /EHsc ./*.cc /std:c++20 -I D:\workspace\asio\asio\include -D_WIN32_WINNT=0x0601 /wd4819 /Fe:kxsvr.exe
//  cl /EHsc ./*.cc /std:c++20 -I D:\workspace\asio\asio\include -D_WIN32_WINNT=0x0601 /wd4819 /Fe:kxsvr.exe  -DUSING_PQ_DB_ -ID:\\workspace\\libpqxx\\include -ID:\\workspace\\libpqxx\\build\\include -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib pqxx.lib libpq.lib