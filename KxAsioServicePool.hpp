#include <asio.hpp>
#include <vector>

class KxAsioIOServicePool
{
public:
	using IOService = asio::io_context;
	using Work = asio::io_context::work;
	using WorkPtr = std::unique_ptr<Work>;
	~KxAsioIOServicePool();
	KxAsioIOServicePool(const KxAsioIOServicePool &) = delete;
	KxAsioIOServicePool &operator=(const KxAsioIOServicePool &) = delete;
	// ʹ round-robin ķʽһ io_service
	asio::io_context &GetIOService();
	void Stop();

	static KxAsioIOServicePool &GetInstance();

private:
	KxAsioIOServicePool(std::size_t size);
	std::vector<IOService> _ioServices;
	std::vector<WorkPtr> _works;
	std::vector<std::thread> _threads;
	std::size_t _nextIOService;
};