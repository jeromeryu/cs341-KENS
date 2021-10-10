/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {


struct Connection
{
	int fd;
	int pid;
	int cnt;
};


struct Accept
{
	UUID syscallUUID;
	int pid;
  int fd;
	struct sockaddr *addr;
	socklen_t *addrlen;
};

enum SocketState{CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED};

struct Socket{
  int fd;
  int pid;
  struct sockaddr_in addr;
  socklen_t addrlen;
  SocketState state;
  int backlog;
  struct sockaddr_in dstaddr;
  socklen_t dstaddrlen;
  uint32_t seq;
  UUID syscallUUID;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  //std::map<int, DataHolder> socketMap;
  std::list<Socket> socketList;
  std::list<Accept> acceptList;
  std::list<Connection> connectionList;

  void syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol);
  void syscall_close(UUID syscallUUID, int pid, int fd);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
