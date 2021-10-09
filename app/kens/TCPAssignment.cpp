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
  std::list<Socket>::iterator it;

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
  in_addr_t ip_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

  std::list<Socket>::iterator it;
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
  }

  struct Socket socket;
  socket.fd = sockfd;
  socket.addrlen = addrlen;
  socket.pid = pid;
  memcpy(&socket.addr, addr, addrlen);
  socket.state = SocketState::CLOSED;
  std::cout<<"bind "<< socket.state<<std::endl;
  if(ret!=-1){
    socketList.push_back(socket);
  }
  this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  std::list<Socket>::iterator it;
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

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  int ret = 0;


  uint8_t* tmp = (uint8_t*)(&((sockaddr_in*)addr)->sin_addr.s_addr);
  ipv4_t dstip;
  for(int i=0; i<4; i++){
    dstip[i] = tmp[i];
  }

  int nicport = getRoutingTable(dstip); // retrieve NIC port
  std::cout<<"nic port : "<<nicport<<std::endl;
  std::optional<ipv4_t> srcip = getIPAddr(nicport); // retrieve the source IP address

  ipv4_t t = *srcip;

  uint32_t tmp2 = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);
	srand((unsigned)time(NULL));
  int srcport = rand();

  struct Socket socket;
  socket.fd = sockfd;
  socket.addr.sin_family = AF_INET;
	memcpy(&(socket.addr.sin_addr.s_addr), &tmp2, 4);
  socket.addr.sin_port = srcport;
  socket.addrlen = sizeof(socket.addr);
  memcpy(&socket.dstaddr, addr, addrlen);
  socket.dstaddrlen = addrlen;
  socket.state = SocketState::CLOSED;
  socket.pid = pid;
  
  socketList.push_back(socket);
  //socket = socketList.back();

	Packet synPacket = Packet(54);

  int tcp_start = 34;
  int ip_start = 14;

  synPacket.writeData(ip_start + 12, &socket.addr.sin_addr.s_addr, 4);
  synPacket.writeData(ip_start + 16, &socket.dstaddr.sin_addr.s_addr, 4);
  synPacket.writeData(tcp_start, &socket.addr.sin_port, 2);
  synPacket.writeData(tcp_start+2, &socket.dstaddr.sin_port, 2);

  srand((unsigned int)time(NULL));
  socket.seq = rand();
  uint32_t seq = htonl(socket.seq);
  synPacket.writeData(tcp_start+4, &seq, 4);

	uint16_t buf1 = 0;
  buf1 += 5 << 12; 
  buf1 +=  1 << 1; // SYN
  buf1 = htons(buf1);
  synPacket.writeData(tcp_start+12, (uint8_t*)&(buf1), 2);
  buf1 = htons(51200);
  synPacket.writeData(tcp_start+14, (uint8_t*)&(buf1), 2); //window size
  
  uint8_t buf2[20];
	synPacket.readData(tcp_start, buf2, 20);
	buf1 = NetworkUtil::tcp_sum(socket.addr.sin_addr.s_addr, socket.dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
	buf1 = ~buf1;
	buf1 = htons(buf1);
	synPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);
	socket.state = SocketState::SYN_SENT;
  this->sendPacket("IPv4", std::move(synPacket)); //sendp packet

  std::cout<<"send "<< socket.state<<std::endl;
  
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  std::list<Socket>::iterator it;
  bool exist = false;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    if(it->state==ESTABLISHED && it->fd==sockfd){
      exist = true;
      break;
    }
  }
  if(exist){
    it->fd = createFileDescriptor(pid);
    memcpy(addr, &it->dstaddr, sizeof(it->dstaddr));
    *addrlen = it->dstaddrlen;
    returnSystemCall(syscallUUID, it->fd);
  } else {
    //accept ACK packet
    exist = false;
    for(it = socketList.begin(); it != socketList.end(); ++it){
      if(it->fd==sockfd && it->state == SocketState::LISTEN){
        exist = true;
        break;
      }
    }
    if(!exist){
      returnSystemCall(syscallUUID, -1);
    }

    Accept a;
    a.fd = sockfd;
    a.pid = pid;
    a.addr = addr;
    a.addrlen = addrlen;
    acceptList.push_back(a);
  }
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  std::list<Socket>::iterator it;
  bool exist = false;
  std::cout<<"listen"<<std::endl;
  std::cout<<"size "<<socketList.size()<< std::endl; 
  for(it = socketList.begin(); it != socketList.end(); ++it){
    std::cout<<"state "<<it->state<<std::endl;
    std::cout<<"fd "<<it->fd<<" "<<sockfd<<std::endl;
    if(it->state==CLOSED && it->fd==sockfd){
      exist = true;
      break;
    }
  }
  if(exist){
    std::cout<<"listen"<<std::endl;
    it->state = SocketState::LISTEN;
    it->backlog = backlog;


    returnSystemCall(syscallUUID, 0);
  } else {
    returnSystemCall(syscallUUID, -1);
  }
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;
  std::cout<<"syscall "<<param.syscallNumber<<std::endl;
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
    this->syscall_connect(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int,
    param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
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
  // (void)fromModule;
  // (void)packet;

	if(fromModule.compare("IPv4") == 0){
    int tcp_start = 34;
    int ip_start = 14;
		uint16_t srcport, dstport;
    uint32_t srcip, dstip;
		packet.readData(tcp_start+0, &srcport, 2);
		packet.readData(tcp_start+2, &dstport, 2);
    packet.readData(ip_start+12, &srcip, 4);
    packet.readData(ip_start+16, &dstip, 4);

  	uint8_t tcpheader[20];
    packet.readData(tcp_start, tcpheader, 20);

    uint8_t flags;
		packet.readData(tcp_start+13, &flags, 1);
    
		uint32_t ack;
		packet.readData(tcp_start+8, &ack, 4);
		ack = ntohl(ack);

		std::list<Socket>::iterator it;
    bool exist = false;

    if((~flags & (1<<4)) && (flags & (1<<1))){
      //SYN packet
      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port==dstport 
            && (it->addr.sin_addr.s_addr == dstip || it->addr.sin_addr.s_addr==0)
            && it->state == SocketState::LISTEN){
          exist = true;
          break;
        }
      }
      if(!exist){
        return;
      }

      std::cout<<"received syn packet"<<std::endl;
      // Socket socket;
      // socket.addr.sin_addr.s_addr = dstip;
      // socket.addr.sin_port = dstport;
      // socket.addr.sin_family = AF_INET;
      // socket.addrlen = sizeof(socket.addr);
      // socket.dstaddr.sin_addr.s_addr = srcip;
      // socket.dstaddr.sin_port = srcport;
      // socket.dstaddr.sin_family = AF_INET;
      // socket.dstaddrlen = sizeof(socket.dstaddr);
      // socket.state = SocketState::SYN_RCVD;
      // socketList.push_back(socket);
      //it->state == SocketState::SYN_RCVD;

      it->dstaddr.sin_addr.s_addr = srcip;
      it->dstaddr.sin_port = srcport;
      it->dstaddr.sin_family = AF_INET;
      it->dstaddrlen = sizeof(it->dstaddr);

			uint32_t newack;
			packet.readData(tcp_start+4, &newack, 4);
			newack = ntohl(newack);
			newack++;
			newack = htonl(newack);

      Packet newPacket(54);

      newPacket.writeData(ip_start + 12, &it->addr.sin_addr.s_addr, 4);
      newPacket.writeData(ip_start + 16, &it->dstaddr.sin_addr.s_addr, 4);
      newPacket.writeData(tcp_start, &it->addr.sin_port, 2);
      newPacket.writeData(tcp_start+2, &it->dstaddr.sin_port, 2);

      srand((unsigned int)time(NULL));
      it->seq = rand();
      uint32_t seq = htonl(it->seq);
      newPacket.writeData(tcp_start+4, &seq, 4); //seq

      newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


      uint16_t buf1 = 0;
      buf1 += 5 << 12; 
      buf1 +=  1 << 4; // ACK
      buf1 += 1 << 1; //SYN
      buf1 = htons(buf1);
      newPacket.writeData(tcp_start+12, (uint8_t*)&(buf1), 2);
      buf1 = htons(51200);
      newPacket.writeData(tcp_start+14, (uint8_t*)&(buf1), 2); //window size
      
      uint8_t buf2[20];
      newPacket.readData(tcp_start, buf2, 20);
      buf1 = NetworkUtil::tcp_sum(it->addr.sin_addr.s_addr, it->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
      buf1 = ~buf1;
      buf1 = htons(buf1);
      newPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);
      it->state = SYN_RCVD;
      std::cout<<"send syn_ack packet"<<std::endl;
      this->sendPacket("IPv4", std::move(newPacket)); //sendp packet

    } else if((flags & (1<<4)) && (flags & (1<<1))){
      //SYN ACK packet
      for(it=socketList.begin(); it!=socketList.end(); it++){
        // std::cout<<"check 1 "<<it->addr.sin_port<<" "<<dstport<<std::endl;
        // std::cout<<"check 2 "<<it->addr.sin_addr.s_addr<<" "<<dstip<<std::endl;
        // std::cout<<"check 3 "<<it->dstaddr.sin_port<<" "<<srcport<<std::endl;
        // std::cout<<"check 4 "<<it->dstaddr.sin_addr.s_addr<<" "<<srcip<<std::endl;
        // std::cout<<"check 5 "<<it->state<<" "<<SocketState::SYN_SENT<<std::endl;
        // break;

        if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
        && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip
        && it->state == SocketState::SYN_SENT){
          exist = true;
          break;
        }
      }
      
      if(!exist){
        return;
      }
      std::cout<<"exists"<<std::endl;
      if(ack != it->seq +1){
        std::cout<<"here"<<std::endl;
        return;
      }

			uint32_t newack;
			packet.readData(tcp_start+4, &newack, 4);
			newack = ntohl(newack);
			newack++;
			newack = htonl(newack);

      Packet newPacket(54);

      newPacket.writeData(ip_start + 12, &it->addr.sin_addr.s_addr, 4);
      newPacket.writeData(ip_start + 16, &it->dstaddr.sin_addr.s_addr, 4);
      newPacket.writeData(tcp_start, &it->addr.sin_port, 2);
      newPacket.writeData(tcp_start+2, &it->dstaddr.sin_port, 2);

      newPacket.writeData(tcp_start+8, (uint8_t*)&ack, 4); //ack

      uint16_t buf1 = 0;
      buf1 += 5 << 12; 
      buf1 +=  1 << 4; // ACK
      buf1 = htons(buf1);
      newPacket.writeData(tcp_start+12, (uint8_t*)&(buf1), 2);
      buf1 = htons(51200);
      newPacket.writeData(tcp_start+14, (uint8_t*)&(buf1), 2); //window size
      
      uint8_t buf2[20];
      newPacket.readData(tcp_start, buf2, 20);
      buf1 = NetworkUtil::tcp_sum(it->addr.sin_addr.s_addr, it->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
      buf1 = ~buf1;
      buf1 = htons(buf1);
      newPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);
      it->state = ESTABLISHED;
      std::cout<<"send ack packet$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"<<std::endl;
      this->sendPacket("IPv4", std::move(newPacket)); 

    } else if((flags & (1<<4)) && (~flags & (1<<1))){
      //ACK packet
      std::cout<<"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!received ack packet"<<std::endl;

      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
        && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip
        && it->state == SocketState::SYN_RCVD){
          exist=true;
          break;
        }
      }
      if(ack != it->seq +1){
        std::cout<<"wrong seq"<<std::endl;
        return;
      }
      if(!exist){
        return;
      }
      
      it->state == SocketState::ESTABLISHED;

      bool exist2 = false;
      std::list<Accept>::iterator it2;
      for(it2=acceptList.begin(); it2 != acceptList.end(); it2++){
        if(it2->fd==it->fd && it2->pid == it->pid){
          exist2 = true;
          break;
        }
      }
      if(exist2){
        it->fd = createFileDescriptor(it->pid);
        memcpy(it2->addr, &it->dstaddr, sizeof(it->dstaddr));
        *(it2->addrlen) = it->dstaddrlen;
        UUID syscallUUID = it2->syscallUUID;
        acceptList.erase(it2);
        std::cout<<"return ack "<<it->fd<<std::endl;
        returnSystemCall(syscallUUID, it->fd);
      }


    }
		





  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
