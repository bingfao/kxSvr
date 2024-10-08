#include "KxAsioServicePool.hpp"
#include <iostream>
#include "KxLogger.hpp"

KxAsioIOServicePool::KxAsioIOServicePool(std::size_t size ) : _ioServices(size),
															 _works(size), _nextIOService(0)
{
	for (std::size_t i = 0; i < size; ++i)
	{
		_works[i] = std::unique_ptr<Work>(new Work(_ioServices[i]));
	}

	// 遍历多个ioservice，创建多个线程，每个线程内部启动ioservice
	for (std::size_t i = 0; i < _ioServices.size(); ++i)
	{
		_threads.emplace_back([this, i]()
							  { _ioServices[i].run(); });
	}
}

KxAsioIOServicePool::~KxAsioIOServicePool()
{
	//std::cout << "AsioIOServicePool destruct" << std::endl;
	KX_LOG_FUNC_("AsioIOServicePool destruct");
}

asio::io_context &KxAsioIOServicePool::GetIOService()
{
	auto &service = _ioServices[_nextIOService++];
	if (_nextIOService == _ioServices.size())
	{
		_nextIOService = 0;
	}
	return service;
}

void KxAsioIOServicePool::Stop()
{
	for (auto &work : _works)
	{
		work.reset();
	}

	for (auto &t : _threads)
	{
		t.join();
	}
}

KxAsioIOServicePool &KxAsioIOServicePool::GetInstance()
{
	static KxAsioIOServicePool instance(std::thread::hardware_concurrency());
	return instance;
}