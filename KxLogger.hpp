#pragma once

#ifndef _KX_LOG_HPP_
#define _KX_LOG_HPP_

#include <fstream>
#include <string>
#include <thread>
#include <deque>
#include <mutex>
#include <condition_variable>


void KX_LOG_FUNC_(const char* szLog);
void KX_LOG_FUNC_(const std::string& strLog);

class Kx_Logger
{
public:
    Kx_Logger(const char *szPath, const char *szFilePrefix);
    ~Kx_Logger();

public:
    void Log(const char *);
    void LogInfo(const char* szInfo);
    void LogInfo(const std::string& strInfo);
    void OnCheckDayChanged(int nDayOfMon);
    void close();

private:
    void thdFun_doLog();
    void dealOneItem();
    std::ofstream m_of_log;
    std::string m_strPath;
    int m_nDayOfMon;
    std::string m_strFilePrefix;
    // std::string m_strFileName;
    std::thread m_log_thread;
    std::deque<std::string> m_deque_logstr;
    std::mutex m_mtx_deque;
    bool m_b_thdExit;
    std::condition_variable m_cond_consume;
    bool m_bClosed;
};

#endif 