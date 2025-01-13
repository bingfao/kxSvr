
#pragma once

#ifndef _KX_LOG_IOSTREAM_H_
#define _KX_LOG_IOSTREAM_H_

#include <iostream>
#include <iomanip>
#include <sstream>

void KX_LOG_FUNC_(const std::string &strLog)
{
  std::cout << strLog << std::endl;
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


#endif