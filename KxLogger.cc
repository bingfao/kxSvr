#include "KxLogger.hpp"
#include <iostream>
#include <sstream>


const char *cst_szLogFileExt = ".log";

Kx_Logger::Kx_Logger(const char *szPath, const char *szFilePrefix)
    : m_strPath(szPath), m_strFilePrefix(szFilePrefix), m_b_thdExit(false), m_bClosed(false)
{
    const std::chrono::time_point<std::chrono::system_clock> tp_now =
        std::chrono::system_clock::now();
    const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
    auto tm_now = std::localtime(&t_c);
    m_nDayOfMon = tm_now->tm_mday;
    std::string strFileName = m_strPath + '/' + m_strFilePrefix;
    strFileName += std::to_string(m_nDayOfMon);
    strFileName += cst_szLogFileExt;
    m_of_log.open(strFileName, std::ios_base::app);
    if (!m_of_log)
    {
        std::cerr << "OpenLogFile " << strFileName << " Failed." << std::endl;
    }
    else
    {
        // 启动log 线程
        m_log_thread = std::thread(&Kx_Logger::thdFun_doLog, this);
    }
}

Kx_Logger::~Kx_Logger()
{
    close();
}

void Kx_Logger::close()
{
    // 先停止线程
    if (!m_bClosed)
    {
        m_b_thdExit = true;
        m_cond_consume.notify_one();
        if (m_log_thread.joinable())
            m_log_thread.join();
        if (m_of_log)
        {
            m_of_log.close();
        }
        m_bClosed = true;
    }
    // std::unique_lock<std::mutex> lock(m_mtx_deque);
    // m_deque_logstr.clear();
}

void Kx_Logger::Log(const char *szLog)
{
    std::unique_lock<std::mutex> lock(m_mtx_deque);
    m_deque_logstr.emplace_back(szLog);
    if (m_deque_logstr.size() == 1)
    {
        lock.unlock();
        m_cond_consume.notify_one();
    }
}

void Kx_Logger::LogInfo(const char *szInfo)
{
    auto thd_id = std::this_thread::get_id();
    std::ostringstream ss;
    // std::string strinfo = "[thread:";
    ss << "[thread:" << thd_id << "] time: ";
    const std::chrono::time_point<std::chrono::system_clock> tp_now =
        std::chrono::system_clock::now();
    const std::time_t t_c = std::chrono::system_clock::to_time_t(tp_now);
    auto tm_now = std::localtime(&t_c);
    ss << tm_now->tm_hour << ":" << tm_now->tm_min << ":" << tm_now->tm_sec;
    auto now_ms = std::chrono::time_point_cast<std::chrono::microseconds>(tp_now);
    long nMs = now_ms.time_since_epoch().count() % 1000000;
    ss <<"["<< nMs << "] " << szInfo;
    Log(ss.str().c_str());
}

void Kx_Logger::LogInfo(const std::string &strInfo)
{
    LogInfo(strInfo.c_str());
}

void Kx_Logger::OnCheckDayChanged(int nDayOfMon)
{
    if (m_nDayOfMon != nDayOfMon)
    {
        // 需要先暂停当前写文件的操作，然后重新创建文件
        if (m_of_log)
            m_of_log.close();
        m_nDayOfMon = nDayOfMon;
        std::string strFileName = m_strPath + '/' + m_strFilePrefix;
        strFileName += std::to_string(m_nDayOfMon);
        strFileName += cst_szLogFileExt;
        m_of_log.open(strFileName);
        if (!m_of_log)
        {
            std::cerr << "OpenLogFile " << strFileName << " Failed." << std::endl;
        }
    }
}

void Kx_Logger::dealOneItem()
{
    auto item = m_deque_logstr.front();
    if (m_of_log)
    {
        m_of_log << item << std::endl;
    }
    m_deque_logstr.pop_front();
}

void Kx_Logger::thdFun_doLog()
{
    for (;;)
    {
        std::unique_lock<std::mutex> unique_lk(m_mtx_deque);
        // 判断队列为空则用条件变量阻塞等待，并释放锁
        while (m_deque_logstr.empty() && !m_b_thdExit)
        {
            m_cond_consume.wait(unique_lk);
        }
        // 判断是否为关闭状态，把所有逻辑执行完后则退出循环
        if (m_b_thdExit)
        {
            for (auto &item : m_deque_logstr)
            {
                if (m_of_log)
                {
                    m_of_log << item << std::endl;
                }
            }
            m_deque_logstr.clear();
            break;
        }
        else
        {
            dealOneItem();
        }
    }
}