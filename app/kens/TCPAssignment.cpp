/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {}

void TCPAssignment::finalize() {}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol){

  int ret = this->createFileDescriptor(pid);
    this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
  std::list<DataHolder>::iterator it;

  for (it = socketList.begin(); it != socketList.end(); ++it){
    if(it->fd == fd){
      socketList.erase(it);
      break;
    }
  }

	this->removeFileDescriptor(pid, fd);
  this->returnSystemCall(syscallUUID, 0);
}



void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{

  int ret = 0;
  in_port_t port = ((struct sockaddr_in *)addr)->sin_port;
  in_port_t ip_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

  std::list<DataHolder>::iterator it;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    std::cout<<it->addr.sin_addr.s_addr<<std::endl;
    if((it->addr.sin_addr.s_addr == ip_addr) || (it->addr.sin_addr.s_addr == 0)){
      if(port == it->addr.sin_port){
        ret = -1;
        break;
      }
    }
    if(it->fd == sockfd){
      ret = -1;
      break;
    }
    // if(port == it->addr.sin_port){
    //   ret = -1;
    //   break;
    // }
  }

  struct DataHolder dh;
  dh.fd = sockfd;
  dh.addrlen = addrlen;
  memcpy(&dh.addr, addr, addrlen);

  if(ret!=-1){
    socketList.push_back(dh);
  }
  this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  std::list<DataHolder>::iterator it;
  bool exist = false;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    if(it->fd == sockfd){
      exist = true;
      break;
    }
  }

  int ret = -1;
  if(exist){
    memcpy(addr, &it->addr, it->addrlen);
    ret = 0;
  }
  this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;
  // std::cout<<"syscall "<<syscallUUID<<std::endl;
  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,
    param.param2_int, param.param3_int);
    break;
  case CLOSE:
    // std::cout<<"here1 "<<pid<<" "<<param.param1_int<<std::endl;
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case CONNECT:
    // this->syscall_connect(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //(socklen_t)param.param3_int);
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, param.param1_int,
    // param.param2_int);
    break;
  case ACCEPT:
    // this->syscall_accept(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr*>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
    	static_cast<struct sockaddr *>(param.param2_ptr),
    	(socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    //		static_cast<struct sockaddr *>(param.param2_ptr),
    //		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
