#include "net.h"
#include <chrono>

namespace net {

	void NetClient::start(const std::function<void(const Buffer::Ptr&)>& onPacket) {
		this->onPacket = onPacket;
		this->thread = std::thread(loop, this);
	}

	bool NetClient::onRead() {
		const int sizeofLen = sizeof(uint32_t);

		int n = ::recv(socket, &readbuff[readoffset], sizeof(readbuff) - readoffset, 0);
		if (n == SOCKET_ERROR) {
			auto e = WSAGetLastError();
			if (e != WSAEWOULDBLOCK) {
				return false;
			}
		}
		else {
			dataSize += n;
			for (; dataSize >= sizeofLen;) {
				auto packetLen = (int)::ntohl(*reinterpret_cast<uint32_t*>(&readbuff[readoffset]));
				if (packetLen + sizeofLen > sizeof(readbuff)) {
					return false;
				}

				if (dataSize >= packetLen + sizeofLen) {
					dataSize -= (packetLen + sizeofLen);
					readoffset += sizeofLen;
					auto packet = Buffer::New(&readbuff[readoffset], packetLen);
					readoffset += packetLen;
					onPacket(packet);
				}
				else {
					::memmove(&readbuff[0], &readbuff[readoffset], dataSize);
					readoffset = 0;
					break;
				}
			}
		}
		return true;
	}

	bool NetClient::onWrite() {
		mtx.lock();
		for (;;) {
			Buffer::Ptr buff;
			if (!sendqueue.empty()) {
				buff = sendqueue.front();
				sendqueue.pop_front();
				int n = ::send(socket, buff->BuffPtr(), (int)buff->Len(), 0);
				if (n == SOCKET_ERROR) {
					auto e = WSAGetLastError();
					if (e == WSAEWOULDBLOCK) {
						sendqueue.push_front(buff);
						break;
					}
					else {
						mtx.unlock();
						return false;
					}
				}
				else if (n < buff->Len()) {
					sendqueue.push_front(Buffer::New(buff, n, buff->Len()));
				}
			}
			else {
				break;
			}
		}
		mtx.unlock();
		return true;
	}

	bool NetClient::looponce(int ms) {
		fd_set r_set;
		fd_set w_set;
		fd_set e_set;
		FD_ZERO(&r_set);
		FD_ZERO(&w_set);
		FD_ZERO(&e_set);
		FD_SET(socket, &r_set);
		FD_SET(socket, &e_set);
		mtx.lock();
		if (!sendqueue.empty()) {
			FD_SET(socket, &w_set);
		}
		mtx.unlock();

		struct timeval timeout;
		timeout.tv_sec = ms / 1000;
		timeout.tv_usec = (ms % 1000) * 1000;

		auto ok = true;

		int n = ::select(0, &r_set, &w_set, &e_set, &timeout);
		if (n > 0)
		{
			auto ok = true;
			if (FD_ISSET(socket, &e_set) || FD_ISSET(socket, &r_set)) {
				ok = onRead();
			}

			if (ok && FD_ISSET(socket, &w_set)) {
				ok = onWrite();
			}

		}

		return ok;
	}


	void NetClient::loop(NetClient* c) {
		for (; c->die.load() == false;) {
			auto ok = c->looponce(1);
			if (!ok) {
				::closesocket(c->socket);
				for (; c->die.load() == false;) {
					auto s = c->connect(&c->serverAddr);
					if (s == INVALID_SOCKET) {
						std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					}
					else {
						c->socket = s;
						c->mtx.lock();
						c->sendqueue.clear();
						c->mtx.unlock();
					}
				}
			}
		}
	}
}