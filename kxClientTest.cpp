#define WIN32

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <iostream>
#include <thread>
#include <vector>
#include "KxMsgDef.h"

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#endif

#define DEFAULT_BUFLEN 1024

sockaddr_in g_clientService;

const int cst_nSendRecvCount = 1;

std::atomic_int at_unconn;
std::atomic_int at_errsend;
std::atomic_int at_errrecv;

bool g_bExitThread = false;

/* CRC16 implementation acording to CCITT standards */

static const unsigned short crc16tab[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0};

unsigned short crc16_ccitt(const unsigned char *buf, int len)
{
    unsigned short crc = 0;
    for (int counter = 0; counter < len; counter++)
        crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *buf++) & 0x00FF];
    return crc;
}

// #pragma pack(1)

// struct KxMsgHeader_Base
// {
//     unsigned short nMsgId;
//     unsigned char nTypeFlag; // 0 Send, 1: Resp
//     unsigned short nSeqNum;
//     unsigned int nMsgBodyLen;
//     unsigned char nCryptFlag;
//     unsigned char nReserve[3];
//     unsigned short nCrc16;
// };

// class KxMsgRespHeader : public KxMsgHeader_Base
// {
// public:
//     unsigned int nRespCode;

//     KxMsgRespHeader()
//         : KxMsgHeader_Base()
//     {
//         nTypeFlag = cst_Resp_MsgType;
//     }
// };

// class KxMsgHeader : public KxMsgHeader_Base
// {
// public:
//     unsigned int nDevId;
//     unsigned int nSessionId; // 由Svr 分配的sessionId

//     KxMsgHeader()
//         : KxMsgHeader_Base()
//     {
//         nTypeFlag = 0;
//     }
// };

// struct KxDevRegPacketBody
// {
//     unsigned short tmYear;
//     unsigned char tmMonth;
//     unsigned char tmDay;
//     unsigned char tmHour;
//     unsigned char tmMin;
//     unsigned char tmSec;
//     unsigned int nDevHwVersion;
//     unsigned int nDevSoftVersion;
//     unsigned int nMotorCtrlHWVer;
//     unsigned int mMotorCtrlSoftVer;
// };

// struct KxDevStatusPacketBody_Base
// {
//     unsigned char nDevType;
//     double lngPox;
//     double latPos;
//     unsigned int nStatus;
//     unsigned char nSocPercent;
//     unsigned short nVoltage;
//     short nTemperature;
//     unsigned char nSeriesCount;
// };

// struct KxDevRegRespPacketBody
// {
//     unsigned int nDevSessionId;
// };

// #pragma pack()

bool checkMsgHeader(KxMsgHeader_Base *pmsgHeader_base, unsigned int nSessionId)
{
    bool brt(false);
    unsigned short nCrc16 = crc16_ccitt((unsigned char *)pmsgHeader_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
    bool bCrcOk = pmsgHeader_base->nCrc16 == nCrc16;
    brt = bCrcOk;
    // if (pmsgHeader_base->nTypeFlag == 0)
    // {
    //     unsigned int *pExtData = (unsigned int *)((unsigned char *)pmsgHeader_base + sizeof(KxMsgHeader_Base));
    //     if (pExtData[1] != nSessionId)
    //     {
    //         brt = false;
    //     }
    // }
    return brt;
}

void onHandleSvrMsg(const char *pMsg, int nMsgLen, const SOCKET &sock, unsigned char *iv_data)
{
    KxMsgHeader_Base *pmsgHeader_base = (KxMsgHeader_Base *)pMsg;
    std::cout << "Recv SvrMsg: " << pmsgHeader_base->nMsgId << ", seqNum: " << pmsgHeader_base->nSeqNum
              << ", bodyMsgLen: " << pmsgHeader_base->nMsgBodyLen << std::endl;
    // send RespCode
    // 根据不同报文，解析，处理
    switch (pmsgHeader_base->nMsgId)
    {
    case 2001:
    case 2002:
    case 2003:
    case 2020:
    case 2021:
    case 2022:
        {
            // 都需要aes 解密获取原始报文，然后校验
            std::cout<<"next to aes decrpt"<<std::endl;
        }
        break;
    }
    KxMsgRespHeader *pResp = (KxMsgRespHeader *)pMsg;
    pResp->nTypeFlag = cst_Resp_MsgType;
    pResp->nCrc16 = crc16_ccitt((unsigned char *)pmsgHeader_base, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
    pResp->nMsgBodyLen = 0;
    pResp->nRespCode = 0;
    send(sock, pMsg, sizeof(KxMsgRespHeader), 0);
}

void recvfunc(const SOCKET &sock, char *rv_buf, int nbufLen, unsigned int nDevId, unsigned int nSessionId, unsigned char *iv_data)
{
    for (;;)
    {
        int iResult = recv(sock, rv_buf, sizeof(KxMsgHeader_Base), 0);
        if (iResult > 0)
        {
            if (iResult == sizeof(KxMsgHeader_Base))
            {
                KxMsgHeader_Base *pmsgHeader_base = (KxMsgHeader_Base *)rv_buf;
                unsigned int nHeaderExtDataLen = 0;
                if (pmsgHeader_base->nTypeFlag == cst_Resp_MsgType)
                {
                    nHeaderExtDataLen = 4;
                }
                else
                {
                    nHeaderExtDataLen = 8;
                }
                iResult = recv(sock, rv_buf + sizeof(KxMsgHeader_Base), nHeaderExtDataLen, 0);
                if (iResult == nHeaderExtDataLen)
                {
                    if (checkMsgHeader(pmsgHeader_base, nSessionId))
                    {
                        int nPacketLen = pmsgHeader_base->nMsgBodyLen + sizeof(KxMsgHeader_Base) + nHeaderExtDataLen;
                        if (pmsgHeader_base->nMsgBodyLen)
                        {
                            int nbuf_beLeft = nbufLen - (sizeof(KxMsgHeader_Base) + nHeaderExtDataLen);
                            if (nbuf_beLeft > pmsgHeader_base->nMsgBodyLen)
                            {
                                char *pMsgBody = rv_buf + sizeof(KxMsgHeader_Base) + nHeaderExtDataLen;
                                iResult = recv(sock, pMsgBody, pmsgHeader_base->nMsgBodyLen, 0);
                                if (iResult == pmsgHeader_base->nMsgBodyLen)
                                {
                                    // 报文已经全部读出
                                    onHandleSvrMsg(rv_buf, nPacketLen, sock, iv_data);
                                }
                            }
                        }
                        else
                        {
                            onHandleSvrMsg(rv_buf, nPacketLen, sock, iv_data);
                        }
                    }
                    else
                    {
                        std::cout << "devId: " << nDevId << ", invalid msgHeader is " << pmsgHeader_base->nMsgId << std::endl;
                    }
                }
            }
        }
        else
        {
            if (!g_bExitThread)
            {
                if (iResult == 0)
                {
                    //++at_errrecv;
                    std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] Connection closed" << std::endl;
                }
                else
                {
                    std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] recv failed with error: " << WSAGetLastError() << std::endl;
                    ++at_errrecv;
                }
            }
            break;
        }
    }
}

void thread_sendrecv(SOCKET &client_sock, unsigned int nDevId)
{
    // std::this_thread::sleep_for(std::chrono::milliseconds(10));
    int iResult(0);
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    if (client_sock == INVALID_SOCKET)
    {
        std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] socket failed with error: " << WSAGetLastError() << std::endl;
        ++at_unconn;
        return;
    }
    // Connect to server.
    iResult = connect(client_sock, (SOCKADDR *)&g_clientService, sizeof(g_clientService));
    if (iResult == SOCKET_ERROR)
    {
        closesocket(client_sock);
        client_sock = INVALID_SOCKET;
    }

    if (client_sock == INVALID_SOCKET)
    {
        std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] Unable to connect to server! " << std::endl;
        ++at_unconn;
    }
    else
    {
        // Send an DevReg
        unsigned char sendbuf[DEFAULT_BUFLEN] = {0};
        unsigned short nSeqNum = 0;
        KxMsgHeader *pMsgHeader = (KxMsgHeader *)sendbuf;
        pMsgHeader->nMsgId = MSG_DEV_REGISTER;
        pMsgHeader->nSeqNum = nSeqNum;
        pMsgHeader->nMsgBodyLen = sizeof(KxDevRegPacketBody);
        pMsgHeader->nCrc16 = crc16_ccitt((unsigned char *)pMsgHeader, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));
        // auto thread_id = std::this_thread::get_id();
        // pMsgHeader->nDevId = *(unsigned int *)(&thread_id);
        pMsgHeader->nDevId = nDevId;
        int nPacketLen = sizeof(KxMsgHeader) + sizeof(KxDevRegPacketBody);
        iResult = send(client_sock, (const char *)sendbuf, nPacketLen, 0);
        if (iResult == SOCKET_ERROR)
        {
            std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] send err: " << WSAGetLastError() << std::endl;
            ++at_errsend;
        }
        else
        {
            iResult = recv(client_sock, recvbuf, recvbuflen, 0);
            if (iResult > 0)
            {
                // 解析应答报文
                if (iResult >= sizeof(KxMsgRespHeader) + sizeof(KxDevRegRespPacketBody))
                {
                    KxMsgRespHeader *pResp = (KxMsgRespHeader *)recvbuf;
                    if (pResp->nSeqNum == pMsgHeader->nSeqNum && pResp->nMsgId == pMsgHeader->nMsgId)
                    {
                        // if (pResp->nRespCode == cst_nResp_Code_RSETSVR)
                        // {
                        //     unsigned char *pRespBody = (unsigned char *)(recvbuf + sizeof(KxMsgRespHeader));
                        //     unsigned char szSvrIpLen = pRespBody[0];
                        //     char *szSvrIp = (char *)(pRespBody + 1);
                        //     unsigned short *pPort = (unsigned short *)(pRespBody + 1 + szSvrIpLen);
                        //     // 需要重新连接
                        //     sockaddr_in svr;
                        //     svr.sin_family = AF_INET;
                        //     svr.sin_addr.s_addr = inet_addr(szSvrIp);
                        //     svr.sin_port = htons(*pPort);
                        //     closesocket(client_sock);
                        //     SOCKET svrSock = INVALID_SOCKET;
                        //     svrSock = socket(AF_INET, SOCK_STREAM,
                        //                      IPPROTO_TCP);
                        //     iResult = connect(svrSock, (SOCKADDR *)&svr, sizeof(svr));
                        //     if (iResult == SOCKET_ERROR)
                        //     {
                        //         closesocket(svrSock);
                        //         svrSock = INVALID_SOCKET;
                        //     }
                        //     if (svrSock != INVALID_SOCKET)
                        //     {
                        //         client_sock = svrSock;
                        //         nPacketLen = sizeof(KxMsgHeader) + sizeof(KxDevRegPacketBody);
                        //         iResult = send(svrSock, (const char *)sendbuf, nPacketLen, 0);
                        //         if (iResult != SOCKET_ERROR)
                        //         {
                        //             iResult = recv(svrSock, recvbuf, recvbuflen, 0);
                        //             if (iResult <= sizeof(KxMsgRespHeader))
                        //             {
                        //                 pResp = nullptr;
                        //             }
                        //         }
                        //     }
                        // }
                        if (pResp && pResp->nRespCode == cst_nResp_Code_OK)
                        {
                            KxDevRegRespPacketBody *pRespBody = (KxDevRegRespPacketBody *)(recvbuf + sizeof(KxMsgRespHeader));
                            pMsgHeader->nSessionId = pRespBody->nDevSessionId;

                            unsigned char iv_data[AES_IV_BLOCK_SIZE];
                            memcpy(iv_data, pRespBody->szIV, AES_IV_BLOCK_SIZE);

                            // 发送状态信息
                            KxDevStatusPacketBody_Base *pDevStatus = (KxDevStatusPacketBody_Base *)(sendbuf + sizeof(KxMsgHeader));
                            pDevStatus->nDevType = 1;
                            pDevStatus->nProtocolFlag = 1;
                            pDevStatus->lngPos = 121.54409;
                            pDevStatus->latPos = 31.22114;
                            pDevStatus->mileage = 32 * nDevId;
                            // pDevStatus->bDriving = 1;
                            // pDevStatus->speed = 4.8*nDevId;
                            pDevStatus->bMiniBatExist = true;
                            strcpy_s(pDevStatus->szMiniBatteryId, "EEAD2002024991");
                            pDevStatus->miniBatteryStatus.socPercent = 82;
                            pDevStatus->miniBatteryStatus.voltage = 1320;
                            pDevStatus->seriesCount = 1;
                            pDevStatus->batteryExist = true;
                            pDevStatus->chargeFlag = 0;
                            strcpy_s(pDevStatus->szBatteryId, "FFAD2002024991");
                            pDevStatus->batteryStatus.socPercent = 90;
                            pDevStatus->batteryStatus.voltage = 5440;
                            pDevStatus->batteryStatus.temp = 3200;

                            pDevStatus->batteryStatus.current = 0;

                            // std::time_t tm_res = std::time(nullptr);
                            // auto thread_id = std::this_thread::get_id();

                            // int *pStatusLow = (int *)(&pDevStatus->Status);
                            // // int *pStatusHigh = pStatusLow + 1;
                            // *pStatusLow = *(int *)(&tm_res);
                            pDevStatus->Status.lockStatus = 0x0D;
                            pDevStatus->Status.lightStatus = 0x05;
                            pDevStatus->Status.sensorStatus = 0x06;
                            pDevStatus->Status.brakeStatus = 0x33;
                            // *pStatusHigh = *(int *)(&thread_id);
                            // std::cout << "devId: " << nDevId << ", devStatus is: 0x" << std::hex << *pStatusLow << ' '
                            // //  << *pStatusHigh
                            //  << std::dec << std::endl;

                            pMsgHeader->nMsgId = 1002;
                            ++pMsgHeader->nSeqNum;

                            pMsgHeader->nMsgBodyLen = sizeof(KxDevStatusPacketBody_Base);
                            pMsgHeader->nCrc16 = crc16_ccitt((unsigned char *)pMsgHeader, sizeof(KxMsgHeader_Base) - sizeof(unsigned short));

                            nPacketLen = sizeof(KxMsgHeader) + sizeof(KxDevStatusPacketBody_Base);
                            iResult = send(client_sock, (const char *)sendbuf, nPacketLen, 0);
                            if (iResult == SOCKET_ERROR)
                            {
                                std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] send err: " << WSAGetLastError() << std::endl;
                                ++at_errsend;
                            }
                            else
                            {
                                std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] send ok! " << std::endl;
                                iResult = recv(client_sock, recvbuf, recvbuflen, 0);
                                if (iResult > 0)
                                {
                                    pResp = (KxMsgRespHeader *)recvbuf;
                                    if (pResp->nSeqNum == pMsgHeader->nSeqNum && pResp->nTypeFlag == cst_Resp_MsgType)
                                    {
                                        std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] Reced Resp Code: " << pResp->nRespCode << " , MsgId : " << pResp->nMsgId << std::endl;
                                    }
                                    // 继续等待接收数据
                                    recvfunc(client_sock, recvbuf, recvbuflen, pMsgHeader->nDevId, pMsgHeader->nSessionId, iv_data);
                                }
                            }
                        }
                    }
                }
            }
            else if (iResult == 0)
            {
                //++at_errrecv;
                std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] Connection closed" << std::endl;
            }
            else
            {
                std::cout << "devId: " << nDevId << ", thread [" << std::this_thread::get_id() << "] recv failed with error: " << WSAGetLastError() << std::endl;
                ++at_errrecv;
            }
        }

        // shutdown(ConnectSocket, SD_SEND);
        //  cleanup
        if (client_sock != INVALID_SOCKET)
        {
            closesocket(client_sock);
            client_sock = INVALID_SOCKET;
        }
    }
}

int main(int argc, const char **argv)
{
    WSADATA wsaData;

    g_clientService.sin_family = AF_INET;
    const char *cst_szSvr = "127.0.0.1";
    const char *szSvr = cst_szSvr;
    unsigned short nSvrPort = 10086;
    if (argc >= 2)
    {
        szSvr = argv[1];
        if (argc >= 3)
        {
            nSvrPort = atoi(argv[2]);
        }
    }
    g_clientService.sin_addr.s_addr = inet_addr(szSvr);
    g_clientService.sin_port = htons(nSvrPort);

    // Initialize Winsock
    auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        std::cout << "WSAStartup failed with error: " << iResult << std::endl;
        return 1;
    }

    const int nClientCount = 2;
    std::vector<std::thread> vec_thread;
    std::vector<SOCKET> vec_Sock;
    SOCKET sock;
    // const auto start = std::chrono::steady_clock::now();
    unsigned int nDevId = 10001;
    for (auto i = 0; i < nClientCount; ++i)
    {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO::IPPROTO_TCP);
        vec_Sock.push_back(sock);
    }
    for (auto i = 0; i < nClientCount; ++i)
    {
        std::thread th_(thread_sendrecv, std::ref(vec_Sock[i]), nDevId);
        vec_thread.push_back(std::move(th_));
        ++nDevId;
    }
    std::cout << "input q to exit" << std::endl;
    getchar();
    g_bExitThread = true;
    for (auto p : vec_Sock)
    {
        if (p != INVALID_SOCKET)
        {
            closesocket(p);
        }
    }
    vec_Sock.clear();
    for (auto &th : vec_thread)
    {
        th.join();
    }
    vec_thread.clear();
    // const auto end = std::chrono::steady_clock::now();
    // const std::chrono::duration<double> diff = end - start;

    // // std::cout << std::fixed << std::setprecision(9) << std::left;
    // std::cout << "Time to Finish used:  " << diff.count() << std::endl;
    std::cout << "Unable connect: " << at_unconn << ". send err: " << at_errsend << ". recv err: " << at_errrecv << std::endl;
#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}

// cl KxClientTest.cpp /EHsc /std:c++20
