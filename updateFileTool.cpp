#include <iostream>
#include <fstream>
#include "kxLog_iostream.h"
#include <pqxx/pqxx>
#include <openssl/evp.h>

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

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
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0] << " <filePathName> <filename> <filetype> <devid>" << std::endl;
        return 1;
    }
    std::string strfileURL = argv[1];
    // int nLasPos = strfileURL.find_last_of('/');
    // std::string strfileName;
    // int nFileType = std::atoi(argv[2]);
    // int nDevId = std::atoi(argv[3]);
    // if (nLasPos != -1)
    // {
    //     strfileName = strfileURL.substr(nLasPos + 1);
    // }
    // else
    // {
    //     std::cerr << "<filePathName> should have '/'" << std::endl;
    //     return 2;
    // }
    std::string strfileName = argv[2];
    int nFileType = std::atoi(argv[3]);
    int nDevId = std::atoi(argv[4]);

    unsigned int nFileSize(0);
    std::string strFileData;
    if (std::ifstream is{strfileURL, std::ios::binary | std::ios::ate})
    {
        auto size = is.tellg();
        nFileSize = size;
        strFileData.assign(size, '\0'); // construct string to stream size
        is.seekg(0);
        if (is.read(&strFileData[0], size))
        {
            // 计算md5
            unsigned char fileMd5[16] = {0};
            int nMdLen = sizeof(fileMd5);
            Kx_MD5((unsigned char *)strFileData.c_str(), nFileSize,
                   fileMd5, nMdLen);
            KX_LOG_FUNC_(fileMd5,nMdLen);
            is.close();
            try
            {
                // Connect to the database.  You can have multiple connections open
                // at the same time, even to the same database.
#ifdef WIN32
                pqxx::connection c{"postgresql://postgres:gb6205966@localhost/postgres"};
#else
                pqxx::connection c{"postgresql://postgres:bingfao@localhost/kingxun"};
#endif
                std::cout << "Connected to " << c.dbname() << '\n';

                pqxx::work tx{c};
                std::string strsql;
                std::string strFileMd5;
                std::stringstream ss;
                for (auto i = 0; i < nMdLen; ++i)
                {
                    ss << std::setw(2) << std::setfill('0') << std::hex << (short)fileMd5[i] ;
                }
                strFileMd5 = "\\x" + ss.str();
                strsql = std::format("select taskid from \"devFileUpdateTask\" where \"filetype\"= {} and \"filename\" = '{}' \
                    and \"fileURL\"= '{}' and \"fileSize\"= {} and \"fileMD5\"= '{}'",
                                     nFileType, strfileName, strfileURL, nFileSize, strFileMd5);
                //KX_LOG_FUNC_(strsql);
                auto rdev = tx.exec(strsql);
                int taskid(-1);
                if (rdev.size() > 0)
                {
                    auto row_ = rdev[0];
                    taskid = row_[0].as<int>();
                }
                if (taskid == -1)
                {
                    strsql = std::format("INSERT INTO \"devFileUpdateTask\" (\"filetype\",\"filename\",\"fileURL\",\"fileSize\",\"fileMD5\"\
                    ,\"operatorid\" ,\"createdtime\",\"chkpassOpid\",\"chktime\") VALUES ({},'{}','{}',{}, '{}', \
                    'sysOp01', CURRENT_TIMESTAMP,'sysOp02', CURRENT_TIMESTAMP) RETURNING taskid;",
                                         nFileType, strfileName, strfileURL, nFileSize, strFileMd5);
                    rdev = tx.exec(strsql);
                    if (rdev.size() > 0)
                    {
                        auto row_ = rdev[0];
                        taskid = row_[0].as<int>();
                    }
                }
                if (taskid != -1)
                {
                    // 查找devFileUpdateRec是否已存在devid,taskid
                    strsql = std::format("select recid from \"devFileUpdateRec\" where \"taskid\"= {} and \"devid\" = {} ",
                                         taskid, nDevId);
                    rdev = tx.exec(strsql);
                    int recid(-1);
                    if (rdev.size() == 0)
                    {
                        strsql = std::format("INSERT INTO \"devFileUpdateRec\" (\"taskid\",\"devid\",\"devtype\") \
                          VALUES ({},{},1) RETURNING recid;",
                                             taskid, nDevId);
                        rdev = tx.exec(strsql);
                        if (rdev.size() > 0)
                        {
                            auto row_ = rdev[0];
                            recid = row_[0].as<int>();
                        }
                    }
                    else
                    {
                        auto row_ = rdev[0];
                        recid = row_[0].as<int>();
                    }
                    if (recid != -1)
                    {
                        std::cout << "Done OK. recid: " << recid << std::endl;
                    }
                }
                tx.commit();
            }
            catch (std::exception const &e)
            {
                std::cerr << "ERROR: " << e.what() << '\n';
                return 1;
            }
        }
    }
    return 0;
}

// g++ ./updateFileTool.cpp -o ./updateFileTool -std=c++20 -DUSING_PQ_DB_ -lpqxx -lpq -lcrypto

// cl /EHsc /std:c++20 ./updateFileTool.cpp  -D WIN32 -D_WIN32_WINNT=0x0601  ./pqxx.lib -ID:\\workspace\\libpqxx\\include -ID:\\workspace\\libpqxx\\build\\include  libpq.lib -I "C:\\Program Files\\OpenSSL\\include"  D:\openssl\libcrypto.lib