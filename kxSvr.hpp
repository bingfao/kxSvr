
#include <asio.hpp>
#include <memory>
#include <map>
#include <list>

class KxMsgPacket_Basic;
class KxDevSession;
class KxMsgLogicNode;

class KxServer
{
public:
	KxServer(asio::io_context &io_context , short port);
	~KxServer();
	void ClearSession(unsigned int);
	unsigned int GetNewSessionId();
	std::shared_ptr<KxDevSession> getDevSession(unsigned int nDevId);
	bool getDevSessionId(unsigned int nDevId, unsigned int &nSessionId);
	void updateDevSessionIdMap(unsigned int nDevId, unsigned int nSessionId);
	void stop();
	void addSvrMsgWaitResp(std::shared_ptr<KxMsgLogicNode>);
	void onMsgResp(std::shared_ptr<KxMsgPacket_Basic> resp);
    unsigned int  getDevCount(){
		return m_devIdSession_Map.size();
	}
private:
	void HandleAccept(std::shared_ptr<KxDevSession>, const asio::error_code &error);
	void StartAccept();
	void StartCheckTimeOutSessions();
	void CheckTimeOutSessions(const std::error_code & /*e*/,
                asio::steady_timer *t);
    void CheckTimeOutSvrMsgWaitItem(const std::time_t& );
	asio::io_context &m_io_context;
	unsigned int m_nsessionCount;
	short m_nPort;
	asio::ip::tcp::acceptor m_acceptor;

	std::map<unsigned int, std::shared_ptr<KxDevSession>> m_sessionsMap;  //key: sessionId
	std::map<unsigned int, unsigned int> m_devIdSession_Map;   //key: devId,value sessionId
	std::mutex m_mutex_map;
	std::list<std::shared_ptr<KxMsgLogicNode>> m_svrMsgWaitResp_list;
	std::mutex m_svrMsgList_mutex;
};