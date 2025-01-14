#pragma once

#include <thread>
#include <queue>
#include <mutex>
#include <map>
#include <functional>
#include <memory>
#include <condition_variable>

class KxDevSession;
class KxBussinessLogicNode;
class KxMsgPacket_Basic;
class KxMsgLogicNode;


typedef std::function<void(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket)> FunCallBack;

class KxBusinessLogicMgr
{
public:
	~KxBusinessLogicMgr();
	void PostMsgToQue(std::shared_ptr<KxBussinessLogicNode> msg);
	void AddMsgWaitResp(std::shared_ptr<KxMsgLogicNode> msg);
	static KxBusinessLogicMgr &GetInstance();

private:
	KxBusinessLogicMgr();
    void DealMsg();
    void dealOneMsg();
    void RegisterCallBacks();
    void DevRegMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic &msgPacket);
    void DevStatusMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void DevUsedTrafficMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void DevGetFileDataMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void DevGetFileOKMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);

	void AppCtrlOpenLockMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void AppCtrlLockDevMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void AppCtrlDevGuardMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void AppCtrlDevElecLockCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void AppCtrlDevFileDeliverCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic &msgPacket);

	void WebSvrRegMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	void WebSvrHeartBeatMsgCallBack(std::shared_ptr<KxDevSession>, const KxMsgPacket_Basic& msgPacket);
	std::thread m_worker_thread;
	std::queue<std::shared_ptr<KxBussinessLogicNode>> m_recvedMsg_que;
	std::mutex m_mutex;
	std::condition_variable m_cond_consume;
	bool _b_stop;
	std::map<short, FunCallBack> m_map_FunCallbacks;
	// std::list<std::shared_ptr<KxMsgLogicNode>> m_svrMsgWaitResp_list;
};