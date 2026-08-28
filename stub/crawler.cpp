#include "crawler.hpp"
#include "log.hpp"
#include <iostream>
#include <syncstream>
#include <cstdio>
#include <cstdlib>
#include <list>
#include <thread>
#include <mutex>
#include <atomic>
#include <pwd.h>
#include <unistd.h>

class thread_data
{
private:
	std::list<fs::path> files;
	std::atomic<unsigned int> running;
	std::mutex mfiles;
	std::mutex mstart;
	unsigned int max_threads;

public:
	thread_data()
	{
		files = std::list<fs::path>();
		max_threads = std::thread::hardware_concurrency();
		std::atomic_store(&running, 0);
	}

	bool CanStart(void)
	{
		return (CurrentlyRunning() < max_threads);
	}

	void StartWhenAvailable(void)
	{
		while (!CanStart())
			std::this_thread::sleep_for(std::chrono::microseconds(100));
		AddRunning();
	}

	unsigned int CurrentlyRunning(void)
	{
		return std::atomic_load(&running);
	}

	unsigned int AddRunning(void)
	{
		return std::atomic_fetch_add(&running, 1);
	}

	unsigned int SubRunning(void)
	{
		return std::atomic_fetch_sub(&running, 1);
	}

	void AddPathToFileList(fs::path p)
	{
		{
			std::scoped_lock lock(mfiles);
			files.push_back(p);
		}
	}
	void MergeList(std::list<fs::path> lp)
	{
		{
			std::scoped_lock lock(mfiles);
			files.merge(lp);
		}
	}
	std::list<fs::path> &GetFiles(void)
	{
		return files;
	}
};

class Crawler
{

private:
	fs::path cwd;
	std::list<fs::path> files;
	thread_data *endpoint;
	bool error;

public:
	Crawler(fs::path target, thread_data *data)
	{
		error = false;
		files = std::list<fs::path>();
		endpoint = data;
		cwd = target;

		try
		{
			fs::current_path(cwd);
		}
		catch (const fs::filesystem_error &e)
		{
			error = true;
		}
	}
	std::list<fs::path> Glob()
	{
		std::list<fs::path> dl;
		for (fs::directory_entry const &entry : fs::directory_iterator(cwd))
			if (entry.is_directory() && !entry.is_symlink())
				dl.push_back(entry.path());
			else if (entry.is_regular_file() && !entry.is_symlink())
				files.push_back(entry.path());
		endpoint->MergeList(files);

		return dl;
	}
	static void Run(fs::path target, thread_data *data)
	{
		data->StartWhenAvailable();
		Crawler instance(target, data);
		if (instance.error)
			return;
		std::list<fs::path> subdirs = instance.Glob();
		data->SubRunning();
		std::list<std::jthread> children = std::list<std::jthread>();

		for (auto &&dir : subdirs)
			children.push_back(std::jthread{&Crawler::Run, dir, data});
		for (auto &&child : children)
			child.join();
	}
	~Crawler() {}
};

std::list<std::string> RetrieveFilesFrom(fs::path from)
{
	std::list<std::string> lst = std::list<std::string>();
	thread_data *td = new thread_data();
	std::thread parent(&Crawler::Run, from, td);

	parent.join();
	for (auto &&file : td->GetFiles())
		lst.push_back(file.string());
	delete td;
	return lst;
}
