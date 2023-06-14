#pragma once
#include <mutex>
#include <thread>
#include <winsock2.h>
#include <WinBase.h>
#include <Winerror.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <list>
#include <functional>
#include "./buffer.h"


namespace net {
	class NetClient : public std::enable_shared_from_this<NetClient> {
	public:
		typedef std::shared_ptr<NetClient> Ptr;

		static NetClient::Ptr New(const std::string &ip,uint32_t port, const std::function<void(const Buffer::Ptr&)> onPacket) {
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons((u_short)port);
			int ret = inet_pton(AF_INET, ip.c_str(), &addr.sin_addr.s_addr);
			auto sock = NetClient::connect(&addr);
			if (sock == INVALID_SOCKET) {
				auto err = ::WSAGetLastError();
				return nullptr;
			}
			else {
				auto ptr = Ptr(new NetClient(addr, sock));
				ptr->start(onPacket);
				return ptr;
			}
		}



		void Send(const Buffer::Ptr &buff) {
			mtx.lock();
			sendqueue.push_back(buff);
			mtx.unlock();
		}

		~NetClient() {
			::closesocket(socket);
			die.store(true);
			thread.join();
		}

	private:

		NetClient(struct sockaddr_in addr, SOCKET socket):serverAddr(addr),socket(socket),readoffset(0),dataSize(0),die(false) {}

		void start(const std::function<void(const Buffer::Ptr&)> &onPacket);
		static void loop(NetClient *c);
		bool looponce(int ms);

		bool onRead();
		bool onWrite();


		static bool SetNonBlock(SOCKET sock) {
			int ioctlvar = 1;
			auto ret = ioctlsocket(sock, FIONBIO, (unsigned long*)&ioctlvar);
			if (ret != 0) {
				return false;
			}
			return true;
		}

		static SOCKET connect(struct sockaddr_in *addr) {
			SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			int ret = ::connect(sock, (struct sockaddr *)addr, sizeof(*addr));
			if (ret >= 0){
				SetNonBlock(sock);
				return sock;
			}
			else {
				::closesocket(sock);
				return INVALID_SOCKET;
			}
		}

		struct sockaddr_in serverAddr;
		SOCKET             socket;
		std::mutex		   mtx;
		std::list<Buffer::Ptr>    sendqueue;
		std::thread        thread;
		std::function<void(const Buffer::Ptr&)> onPacket;
		char  readbuff[1024*64];
		int   readoffset;
		int   dataSize;
		std::atomic_bool die;

	};
}