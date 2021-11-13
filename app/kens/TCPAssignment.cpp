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
#include <E/E_TimeUtil.hpp>
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
  struct Socket *closeSocket;
  bool exist = false;
  for (it = socketList.begin(); it != socketList.end(); ++it){
    if(it->fd == fd && it->pid == pid &&(it->state == SYN_RCVD || it->state == ESTABLISHED || it->state == CLOSE_WAIT)){
      closeSocket = &(*it);
      exist = true;
      break;
    }
  }

  if(!exist){
    exist = false;
    for (it = socketList.begin(); it != socketList.end(); ++it){
      if(it->fd == fd && it->pid == pid &&(it->state == CLOSED)){
        exist = true;
        break;
      }
    }
    if(exist){
      socketList.erase(it);
      removeFileDescriptor(pid, fd);
      returnSystemCall(syscallUUID, 0);
    }else{
      removeFileDescriptor(pid, fd);
      returnSystemCall(syscallUUID, 0);
    }
    return ;
  }

  int tcp_start = 34;
  int ip_start = 14;

  Packet newPacket(54);
  newPacket.writeData(ip_start + 12, (uint8_t*)&closeSocket->addr.sin_addr.s_addr, 4);
  newPacket.writeData(ip_start + 16, (uint8_t*)&closeSocket->dstaddr.sin_addr.s_addr, 4);
  newPacket.writeData(tcp_start, (uint8_t*)&closeSocket->addr.sin_port, 2);
  newPacket.writeData(tcp_start+2, (uint8_t*)&closeSocket->dstaddr.sin_port, 2);

  // uint32_t newseq = htonl(closeSocket->lastsendSeq);
  uint32_t newseq = htonl(closeSocket->nextsendSeq);
  uint32_t newack = htonl(closeSocket->lastsendAck);

  newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
  newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


  uint16_t buf1 = 0;
  buf1 += 5 << 12; 
  buf1 +=  1 << 4;
  buf1 += 1; //FIN_ACK
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


  if(closeSocket->state == SocketState::SYN_RCVD || closeSocket->state == SocketState::ESTABLISHED){
    closeSocket->state = SocketState::FIN_WAIT1;
    closeSocket->lastsendSeq = ntohl(newseq);
    closeSocket->lastsendAck = ntohl(newack);
  }else if(closeSocket->state == SocketState::CLOSE_WAIT){
    closeSocket->state = SocketState::LAST_ACK;
    // if(closeSocket->readWaiting){
    //   size_t temp = closeSocket->readbuffersize;
    //   for(int i=0; i < closeSocket->readbuffersize; i++){
    //     uint8_t a = closeSocket->readbuffer->front();
    //     memcpy((closeSocket->wait.buf+i), &a, 1);
    //     closeSocket->readbuffer->pop_front();
    //   }
    //   closeSocket->readbuffersize = 0;
    //   closeSocket->readWaiting = false;
    //   returnSystemCall(closeSocket->wait.syscallUUID, temp);
    // }
  }
  closeSocket->closesyscall = syscallUUID;

  sendPacket("IPv4", std::move(newPacket));


	// this->removeFileDescriptor(pid, fd);
  // this->returnSystemCall(syscallUUID, 0);
}



void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
  int ret = 0;
  in_port_t port = ((struct sockaddr_in *)addr)->sin_port;
  in_addr_t ip_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

  std::list<Socket>::iterator it;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    if((it->addr.sin_addr.s_addr == ip_addr) || (it->addr.sin_addr.s_addr == 0)){
      if(port == it->addr.sin_port){
        ret = -1;
        break;
      }
    }
    if(it->fd == sockfd && it->pid == pid){
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
  if(ret!=-1){
    socketList.push_back(socket);
  }
  this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  std::list<Socket>::iterator it;
  bool exist = false;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    if(it->fd == sockfd && it->pid == pid){
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
  std::optional<ipv4_t> srcip = getIPAddr(nicport); // retrieve the source IP address

  ipv4_t t = *srcip;

  uint32_t tmp2 = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);
	srand((unsigned)time(NULL));
  int srcport = rand();

  std::list<Socket>::iterator it;
  bool portexists = false;

  for(it=socketList.begin(); it!=socketList.end(); it++){
    if(it->addr.sin_addr.s_addr==tmp2){
      srcport = it->addr.sin_port+0;
      portexists = true;
      break;
    }
  }

  struct Socket *socket = (struct Socket*)malloc(sizeof(Socket));
  if(portexists){
    //for simultaneous connection
    socket = &(*it);
  } 

  socket->fd = sockfd;
  socket->addr.sin_family = AF_INET;
  memcpy(&(socket->addr.sin_addr.s_addr), &tmp2, 4);
  socket->addr.sin_port = srcport;
  socket->addrlen = sizeof(socket->addr);
  memcpy(&socket->dstaddr, addr, addrlen);
  socket->dstaddrlen = addrlen;
  socket->state = SocketState::CLOSED;
  socket->pid = pid;
  socket->syscallUUID = syscallUUID;
  socket->simul = false;
  socket->readbuffer = new std::list<uint8_t>;
  socket->readbuffersize = 0;
  socket->readWaiting = false;
  socket->writebuffer = new std::list<uint8_t>;
  socket->writebuffersize = 0;
  socket->lastdatasendSeq = 0;
  socket->lastdatasendAck = 0;
  socket->retransmit = new std::list<packetdata>;
  socket->EstimatedRTT = 100000000;
  socket->DevRTT = 0;
  socket->SampleRTT = 0;
  socket->TimeoutInterval = socket->EstimatedRTT + 4 * socket->DevRTT;
  
	Packet synPacket = Packet(54);

  int tcp_start = 34;
  int ip_start = 14;

  synPacket.writeData(ip_start + 12, &socket->addr.sin_addr.s_addr, 4);
  synPacket.writeData(ip_start + 16, &socket->dstaddr.sin_addr.s_addr, 4);
  synPacket.writeData(tcp_start, &socket->addr.sin_port, 2);
  synPacket.writeData(tcp_start+2, &socket->dstaddr.sin_port, 2);

  srand((unsigned int)time(NULL));
  socket->seq = rand();
  uint32_t seq = htonl(socket->seq);
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
	buf1 = NetworkUtil::tcp_sum(socket->addr.sin_addr.s_addr, socket->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
	buf1 = ~buf1;
	buf1 = htons(buf1);
	synPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);
	socket->state = SocketState::SYN_SENT;
  
  
  struct packetdata *retransmitPacket = (struct packetdata *)malloc(sizeof(struct packetdata));
  retransmitPacket->state = PacketState::SYN;
  retransmitPacket->seq = ntohl(seq);
  retransmitPacket->ack = 0;
  retransmitPacket->requiredack = 0;
  retransmitPacket->packetlist = new std::list<Packet>;
  retransmitPacket->packetlist->push_back(synPacket);
  retransmitPacket->sendTime = getCurrentTime();

  this->sendPacket("IPv4", std::move(synPacket)); //sendp packet


  Time retrans = E::TimeUtil::makeTime(socket->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
  retransmitPacket->timersyscall = addTimer(socket, retrans);
  socket->retransmit->push_back(*retransmitPacket);

  if(!portexists){
    socketList.push_back(*socket);
  }
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  std::list<Socket>::iterator it;
  bool exist = false;

  for(it = socketList.begin(); it != socketList.end(); ++it){
    if((it->state==ESTABLISHED || it->state==CLOSE_WAIT) && it->fd==sockfd && it->pid == pid){
      exist = true;
      break;
    }
  }
  if(exist){
    it->fd = createFileDescriptor(pid);
    memcpy(addr, &it->dstaddr, sizeof(it->dstaddr));
    *addrlen = it->dstaddrlen;
    in_port_t port = ((struct sockaddr_in *)addr)->sin_port;
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
    a.syscallUUID = syscallUUID;
    acceptList.push_back(a);
  }
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
  std::list<Socket>::iterator it;
  bool exist = false;
  for(it = socketList.begin(); it != socketList.end(); ++it){
    if(it->state==CLOSED && it->fd==sockfd){
      exist = true;
      break;
    }
  }
  if(exist){
    it->state = SocketState::LISTEN;
    it->backlog = backlog;

    struct Connection c;
    c.pid = pid;
    c.fd = sockfd;
    c.cnt = backlog;
    connectionList.push_back(c);

    returnSystemCall(syscallUUID, 0);
  } else {
    returnSystemCall(syscallUUID, -1);
  }
}
  
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  int ret = -1;
  std::list<Socket>::iterator it;
  for(it = socketList.begin(); it != socketList.end(); it++){
    if(it->fd == sockfd && it->pid == pid){
      memcpy(addr, &it->dstaddr, it->dstaddrlen);
      *addrlen = it->addrlen;
      ret = 0;
      break;
    }
  }
    
  returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count){
  std::list<Socket>::iterator it;
  struct Socket *tar;
  for(it = socketList.begin(); it!= socketList.end(); it++){
    if(it->fd == fd && it->pid == pid && (it->state == SocketState::ESTABLISHED || it->state == SocketState::CLOSE_WAIT)){
      tar = &(*it);
      break;
    }
  }

  if(tar->readbuffersize >= count){
    for(int i=0; i < count; i++){
      uint8_t a = tar->readbuffer->front();
      memcpy((buf+i), &a, 1);
      tar->readbuffer->pop_front();
    }
    tar->readbuffersize -= count;
    returnSystemCall(syscallUUID, count);
  }else{
    tar->wait.syscallUUID = syscallUUID;
    tar->wait.count = count;
    tar->wait.buf = buf;
    tar->wait.read = 0;
    tar->readWaiting = true;
  }

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count){
  std::list<Socket>::iterator it;
  struct Socket *tar;
  for(it = socketList.begin(); it!= socketList.end(); it++){
    if(it->fd == fd && it->pid == pid && (it->state == SocketState::ESTABLISHED || it->state == SocketState::CLOSE_WAIT)){
      tar = &(*it);
      break;
    }
  }

  for(int i = 0; i < count; i++){
    uint8_t a;
    memcpy(&a, (buf+i), 1);
    it->writebuffer->push_back(a);
    it->writebuffersize++;
  }
  size_t total_size = it->writebuffersize;

  returnSystemCall(syscallUUID, total_size);

  while(it->writebuffersize > 0){
    size_t sendsize = (it->writebuffersize > 512) ? 512 : it->writebuffersize;

    int tcp_start = 34;
    int ip_start = 14;

    Packet newPacket(54 + sendsize);
    newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
    newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
    newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
    newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);

    uint32_t newseq;
    uint32_t newack;

    if(it->lastdatasendSeq == 0){
      newseq = it->lastsendSeq;
      it->nextsendSeq = it->lastsendSeq + sendsize;
    }else{
      newseq = it->lastdatasendSeq + sendsize;
      it->nextsendSeq = newseq + sendsize;
    }

    it->lastdatasendAck = it->lastsendAck;
    newack = it->lastdatasendAck;

    it->lastdatasendSeq = newseq;
    it->lastdatasendAck = newack;

    newseq = htonl(newseq);
    newack = htonl(newack);

    newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
    newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


    uint16_t buf1 = 0;
    buf1 += 5 << 12; 
    buf1 +=  1 << 4; //ACK
    buf1 = htons(buf1);
    newPacket.writeData(tcp_start+12, (uint8_t*)&(buf1), 2);
    buf1 = htons(51200);
    newPacket.writeData(tcp_start+14, (uint8_t*)&(buf1), 2); //window size

    for(int i=0; i < sendsize; i++){
      uint8_t a = it->writebuffer->front();
      newPacket.writeData(54+i, (uint8_t *)&(a), 1);
      it->writebuffer->pop_front();
      it->writebuffersize--;
    }

      
    uint8_t buf2[20+sendsize];
    newPacket.readData(tcp_start, buf2, 20+sendsize);
    buf1 = NetworkUtil::tcp_sum(it->addr.sin_addr.s_addr, it->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20+sendsize);
    buf1 = ~buf1;
    buf1 = htons(buf1);
    newPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);


    struct packetdata *retransmitPacket = (struct packetdata *)malloc(sizeof(struct packetdata));
    retransmitPacket->state = PacketState::ACK;
    retransmitPacket->seq = ntohl(newseq);
    retransmitPacket->ack = ntohl(newack);
    retransmitPacket->requiredack = ntohl(newseq) + sendsize;
    retransmitPacket->packetlist = new std::list<Packet>;
    retransmitPacket->packetlist->push_back(newPacket);
    retransmitPacket->sendTime = getCurrentTime();

    this->sendPacket("IPv4", std::move(newPacket)); //sendp packet


    Time retrans = E::TimeUtil::makeTime(it->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
    retransmitPacket->timersyscall = addTimer((Socket *) &(*it), retrans);
    it->retransmit->push_back(*retransmitPacket);
  }


}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {


  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,
    param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
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
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    	static_cast<struct sockaddr *>(param.param2_ptr),
    	static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {

  Time receiveTime = getCurrentTime();

	if(fromModule.compare("IPv4") == 0){
    int tcp_start = 34;
    int ip_start = 14;
		uint16_t srcport, dstport;
    uint32_t srcip, dstip;
		packet.readData(tcp_start+0, &srcport, 2);
		packet.readData(tcp_start+2, &dstport, 2);
    packet.readData(ip_start+12, &srcip, 4);
    packet.readData(ip_start+16, &dstip, 4);

    uint16_t total_length;
    packet.readData(ip_start+2, &total_length, 2);
    total_length = ntohs(total_length);
    total_length -= 20;
		uint8_t buf20[total_length];
		packet.readData(tcp_start+0, buf20, total_length);
		uint16_t cs = NetworkUtil::tcp_sum(srcip, dstip, (uint8_t*)buf20, total_length);
		if(cs!=0xFFFF){
			return;
		}


  	uint8_t tcpheader[20];
    packet.readData(tcp_start, tcpheader, 20);

		uint32_t ack;
		packet.readData(tcp_start+8, &ack, 4);
		ack = ntohl(ack);

		std::list<Socket>::iterator it;
    bool exist = false;

    uint8_t flags;
		packet.readData(tcp_start+13, &flags, 1);


    if(flags == 0x02){
      //SYN packet
      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port==dstport 
            && (it->addr.sin_addr.s_addr == dstip || it->addr.sin_addr.s_addr==0)){
          exist = true;
          break;
        }
      }
      if(!exist){
        return;
      }

      if(it->state==SocketState::LISTEN){
        //simultaneous connection dont come to this part
        bool exist_conn = false;
        std::list<Connection>::iterator it_conn;
        for(it_conn=connectionList.begin(); it_conn != connectionList.end(); it_conn ++){
          if(it_conn->fd == it->fd && it_conn->pid == it->pid){
            exist_conn = true;
            break;
          }
        }
        if(!exist_conn){
          return;
        }
        if(it_conn->cnt <= 0){
          return;
        }
        it_conn->cnt -= 1;
      }

      if(it->state == SocketState::SYN_SENT){
        //for simul connection
        Socket *socket = &(*it);

        uint32_t newack;
        packet.readData(tcp_start+4, &newack, 4);
        newack = ntohl(newack);
        newack++;
        newack = htonl(newack);

        Packet newPacket(54);

        newPacket.writeData(ip_start + 12, (uint8_t*)&socket->addr.sin_addr.s_addr, 4);
        newPacket.writeData(ip_start + 16, (uint8_t*)&socket->dstaddr.sin_addr.s_addr, 4);
        
        newPacket.writeData(tcp_start, (uint8_t*)&socket->addr.sin_port, 2);
        newPacket.writeData(tcp_start+2, (uint8_t*)&socket->dstaddr.sin_port, 2);

        srand((unsigned int)time(NULL));
        socket->seq = rand();

        uint32_t seq = htonl(socket->seq);
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
        buf1 = NetworkUtil::tcp_sum(socket->addr.sin_addr.s_addr, socket->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
        buf1 = ~buf1;
        buf1 = htons(buf1);

        newPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);

        socket->simul = true;
        socket->state = SYN_RCVD;

        struct packetdata *retransmitPacket = (struct packetdata *)malloc(sizeof(struct packetdata));
        retransmitPacket->state = PacketState::SYNACK;
        retransmitPacket->seq = ntohl(seq);
        retransmitPacket->ack = ntohl(newack);
        retransmitPacket->requiredack = 0;
        retransmitPacket->packetlist = new std::list<Packet>;
        retransmitPacket->packetlist->push_back(newPacket);
        retransmitPacket->sendTime = getCurrentTime();

        sendPacket("IPv4", std::move(newPacket));


        Time retrans = E::TimeUtil::makeTime(socket->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
        retransmitPacket->timersyscall = addTimer(socket, retrans);
        socket->retransmit->push_back(*retransmitPacket);

      }else{

        Socket *socket = (struct Socket *)malloc(sizeof(struct Socket));
        socket->addr.sin_addr.s_addr = dstip;
        socket->addr.sin_port = dstport;
        socket->addr.sin_family = AF_INET;
        socket->addrlen = sizeof(socket->addr);
        socket->dstaddr.sin_addr.s_addr = srcip;
        socket->dstaddr.sin_port = srcport;
        socket->dstaddr.sin_family = AF_INET;
        socket->dstaddrlen = sizeof(socket->dstaddr);
        socket->pid = it->pid;
        socket->fd = it->fd;
        socket->simul = false;
        socket->readbuffer = new std::list<uint8_t>;
        socket->readbuffersize = 0;
        socket->readWaiting = false;
        socket->writebuffer = new std::list<uint8_t>;
        socket->writebuffersize = 0;
        socket->lastdatasendSeq = 0;
        socket->lastdatasendAck = 0;
        socket->retransmit = new std::list<packetdata>;
        socket->EstimatedRTT = 100000000;
        socket->DevRTT = 0;
        socket->SampleRTT = 0;
        socket->TimeoutInterval = socket->EstimatedRTT + 4 * socket->DevRTT;

        uint32_t newack;
        packet.readData(tcp_start+4, &newack, 4);
        newack = ntohl(newack);
        newack++;
        newack = htonl(newack);

        Packet newPacket(54);

        newPacket.writeData(ip_start + 12, (uint8_t*)&socket->addr.sin_addr.s_addr, 4);
        newPacket.writeData(ip_start + 16, (uint8_t*)&socket->dstaddr.sin_addr.s_addr, 4);
        
        newPacket.writeData(tcp_start, (uint8_t*)&socket->addr.sin_port, 2);
        newPacket.writeData(tcp_start+2, (uint8_t*)&socket->dstaddr.sin_port, 2);

        srand((unsigned int)time(NULL));
        socket->seq = rand();

        uint32_t seq = htonl(socket->seq);
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
        buf1 = NetworkUtil::tcp_sum(socket->addr.sin_addr.s_addr, socket->dstaddr.sin_addr.s_addr, (uint8_t*)buf2, 20);
        buf1 = ~buf1;
        buf1 = htons(buf1);

        newPacket.writeData(tcp_start+16, (uint8_t*)&buf1, 2);
        socket->state = SYN_RCVD;

        struct packetdata *retransmitPacket = (struct packetdata *)malloc(sizeof(struct packetdata));
        retransmitPacket->state = PacketState::SYNACK;
        retransmitPacket->seq = ntohl(seq);
        retransmitPacket->ack = ntohl(newack);
        retransmitPacket->requiredack = 0;
        retransmitPacket->packetlist = new std::list<Packet>;
        retransmitPacket->packetlist->push_back(newPacket);
        retransmitPacket->sendTime = getCurrentTime();

        sendPacket("IPv4", std::move(newPacket));


        Time retrans = E::TimeUtil::makeTime(socket->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
        retransmitPacket->timersyscall = addTimer(socket, retrans);
        socket->retransmit->push_back(*retransmitPacket);

        socketList.push_back(*socket);
      }

    } else if(flags == 0x12){
      //SYN ACK packet
      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
        && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip){
          exist = true;
          break;
        }
      }
      if(!exist){
        return;
      }
      if(ack != it->seq +1){
        return;
      }

      std::list<packetdata>::iterator temp;
      for(temp = it->retransmit->begin(); temp != it->retransmit->end(); temp++){
        if(temp->state == PacketState::SYN){
          it->SampleRTT = (receiveTime - temp->sendTime) ;
          cancelTimer(temp->timersyscall);
          delete temp->packetlist;
          it->retransmit->erase(temp);
          break;
        }
      }

      it->DevRTT = 0.75 * it->DevRTT + 0.25 * (it->EstimatedRTT > it->SampleRTT ? (it->EstimatedRTT - it->SampleRTT) : (it->SampleRTT - it->EstimatedRTT));
      it->EstimatedRTT = 0.875 * it->EstimatedRTT + 0.125 * it->SampleRTT;
      it->TimeoutInterval = it->EstimatedRTT + 4 * it->DevRTT;

			uint32_t newack;
			packet.readData(tcp_start+4, &newack, 4);
			newack = ntohl(newack);
			newack++;
			newack = htonl(newack);

      Packet newPacket(54);
      newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
      newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
      newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
      newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);

      uint32_t newseq;
      packet.readData(tcp_start+8, &newseq, 4);
      newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
      newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack

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
      it->lastsendSeq = ntohl(newseq);
      it->lastsendAck = ntohl(newack);

      sendPacket("IPv4", std::move(newPacket)); 
      returnSystemCall(it->syscallUUID, 0);

    } else if(flags == 0x10){
      //ACK packet
      AckPacketState ackpacket = ERROR;

      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
        && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip){
          if(it->state == SocketState::ESTABLISHED || it->state == SocketState::CLOSE_WAIT){
            ackpacket = AckPacketState::ACK_DATA;
          }else if(it->state == SocketState::SYN_RCVD){
            ackpacket = AckPacketState::ACK_SYN_RCVD;
          }else if(it->state == SocketState::FIN_WAIT1){
            ackpacket = AckPacketState::ACK_FIN_WAIT1;
          }else if(it->state == SocketState::CLOSING){
            ackpacket = AckPacketState::ACK_CLOSING;
          }else if(it->state == SocketState::LAST_ACK){
            ackpacket = AckPacketState::ACK_LAST_ACK;
          }
          break;
        }
      }
      if((ackpacket == AckPacketState::ACK_DATA) && (total_length > 20)){

        // seq num check
        uint32_t seqcheck;
        packet.readData(tcp_start+4, &seqcheck, 4);
        seqcheck = ntohl(seqcheck);
        bool properpacket = true;

        std::list<packetdata>::iterator find;
        for(find = it->retransmit->begin(); find != it->retransmit->end(); find++){
          if(find->state == PacketState::ACK){
            if(seqcheck != find->ack){
              Packet synPacket = find->packetlist->front();
              this->sendPacket("IPv4", std::move(synPacket));
              properpacket = false;
              break;
            }else{
              it->retransmit->erase(find);
              break;
            }
          }
        }

        if(properpacket){
          Packet newPacket(54);
          newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
          newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
          newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
          newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);

          uint32_t newseq;
          packet.readData(tcp_start+8, &newseq, 4);
          uint32_t newack;
          packet.readData(tcp_start+4, &newack, 4);
          uint16_t total_length;
          packet.readData(ip_start+2, &total_length, 2);
          total_length = ntohs(total_length);
          total_length -= 40;
          newack = ntohl(newack);
          newack += total_length;
          newack = htonl(newack);

          newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
          newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


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


          uint8_t bufdata[total_length];
          packet.readData(tcp_start+20, bufdata, total_length);

          for(int i=0; i < total_length; i++){
            uint8_t a = bufdata[i];
            it->readbuffer->push_back(a);
            it->readbuffersize++;
          }

          if(it->readWaiting && (it->readbuffersize >= it->wait.count)){
            for(int i=0; i < it->wait.count; i++){
              uint8_t a = it->readbuffer->front();
              memcpy((it->wait.buf+i), &a, 1);
              it->readbuffer->pop_front();
              it->readbuffersize--;
            }
            it->readWaiting = false;
            returnSystemCall(it->wait.syscallUUID, it->wait.count);
          }



          struct packetdata *retransmitPacket = (struct packetdata *)malloc(sizeof(struct packetdata));
          retransmitPacket->state = PacketState::ACK;
          retransmitPacket->seq = ntohl(newseq);
          retransmitPacket->ack = ntohl(newack);
          retransmitPacket->requiredack = 0;
          retransmitPacket->packetlist = new std::list<Packet>;
          retransmitPacket->packetlist->push_back(newPacket);
          retransmitPacket->sendTime = getCurrentTime();

          sendPacket("IPv4", std::move(newPacket));

          it->retransmit->push_back(*retransmitPacket);
        }


      }else if(ackpacket == AckPacketState::ACK_DATA){

      }else if(ackpacket == AckPacketState::ACK_SYN_RCVD){
        for(it=socketList.begin(); it!=socketList.end(); it++){
          if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
          && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip
          && it->state == SocketState::SYN_RCVD){
            exist=true;
            break;
          }
        }

        if(ack != it->seq +1){
          return;
        }
        if(!exist){
          return;
        }

        std::list<packetdata>::iterator temp;
        for(temp = it->retransmit->begin(); temp != it->retransmit->end(); temp++){
          if(temp->state == PacketState::SYNACK){
            it->SampleRTT = (receiveTime - temp->sendTime) ;
            cancelTimer(temp->timersyscall);
            delete temp->packetlist;
            it->retransmit->erase(temp);
            break;
          }
        }

        it->DevRTT = 0.75 * it->DevRTT + 0.25 * (it->EstimatedRTT > it->SampleRTT ? (it->EstimatedRTT - it->SampleRTT) : (it->SampleRTT - it->EstimatedRTT));
        it->EstimatedRTT = 0.875 * it->EstimatedRTT + 0.125 * it->SampleRTT;
        it->TimeoutInterval = it->EstimatedRTT + 4 * it->DevRTT;

        it->state = SocketState::ESTABLISHED;

        uint32_t newseq;
        packet.readData(tcp_start+8, &newseq, 4);
        newseq = ntohl(newseq);
        uint32_t newack;
        packet.readData(tcp_start+4, &newack, 4);
        newack = ntohl(newack);

        it->lastsendSeq = newseq;
        it->lastsendAck = newack;


        bool exist_conn = false;
        std::list<Connection>::iterator it_conn;
        for(it_conn=connectionList.begin(); it_conn != connectionList.end(); it_conn ++){
          if(it_conn->fd == it->fd && it_conn->pid == it->pid){
            exist_conn = true;
            break;
          }
        }
        if(!exist_conn){
        }else{
          it_conn->cnt += 1;
        }

        // it_conn->cnt += 1;

        if(it->simul){
          returnSystemCall(it->syscallUUID, 0);
        }
        

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
          in_port_t port = ((struct sockaddr_in *)it2->addr)->sin_port;
          UUID syscallUUID = it2->syscallUUID;
          acceptList.erase(it2);
          returnSystemCall(syscallUUID, it->fd);
        }
      }else if(ackpacket == AckPacketState::ACK_FIN_WAIT1){
        uint32_t seq;
        packet.readData(tcp_start+4, &seq, 4);
        seq = ntohl(seq);
        uint32_t ack;
        packet.readData(tcp_start+8, &ack, 4);
        ack = ntohl(ack);

        std::list<packetdata>::iterator find;
        for(find = it->retransmit->begin(); find != it->retransmit->end(); find++){
          if(find->state == PacketState::ACK && find->requiredack == ack){
            it->SampleRTT = (receiveTime - find->sendTime) ;
            cancelTimer(find->timersyscall);
            delete find->packetlist;
            it->retransmit->erase(find);
            it->DevRTT = 0.75 * it->DevRTT + 0.25 * (it->EstimatedRTT > it->SampleRTT ? (it->EstimatedRTT - it->SampleRTT) : (it->SampleRTT - it->EstimatedRTT));
            it->EstimatedRTT = 0.875 * it->EstimatedRTT + 0.125 * it->SampleRTT;  
            it->TimeoutInterval = it->EstimatedRTT + 4 * it->DevRTT;
            break;
          }else if(find->state == PacketState::ACK && (find->requiredack < ack)){
            it->SampleRTT = (receiveTime - find->sendTime) ;
            cancelTimer(find->timersyscall);
            delete find->packetlist;
            it->retransmit->erase(find);
            break;
          }
        }


        if((it->lastsendSeq+1 == ack) && (it->lastsendAck) == seq){
          if(it->readWaiting){
            size_t temp = it->readbuffersize;
            for(int i=0; i < it->readbuffersize; i++){
              uint8_t a = it->readbuffer->front();
              memcpy((it->wait.buf+i), &a, 1);
              it->readbuffer->pop_front();
            }
            it->readbuffersize = 0;
            it->readWaiting = false;
            returnSystemCall(it->wait.syscallUUID, temp);
          }
          it->state = SocketState::FIN_WAIT2;
        }
      }else if(ackpacket == AckPacketState::ACK_CLOSING){
        it->state = SocketState::TIME_WAIT;

        Time twomsl = E::TimeUtil::makeTime(5, E::TimeUtil::stringToTimeUnit("sec"));
        addTimer((Socket *) &(*it), twomsl);

      }else if(ackpacket == AckPacketState::ACK_LAST_ACK){

        UUID closeUUID = it->closesyscall;
        removeFileDescriptor(it->pid, it->fd);
        socketList.erase(it);
        returnSystemCall(closeUUID, 0);
      }
    }else if(flags == 0x11){
      //FIN,ACK

      for(it=socketList.begin(); it!=socketList.end(); it++){
        if(it->addr.sin_port == dstport && it->addr.sin_addr.s_addr==dstip 
        && it->dstaddr.sin_port == srcport && it->dstaddr.sin_addr.s_addr == srcip){
          exist = true;
          break;
        }
      }

      if(it->state == SocketState::FIN_WAIT1){
        int tcp_start = 34;
        int ip_start = 14;

        Packet newPacket(54);
        newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
        newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
        newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
        newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);


        uint32_t newseq;
        packet.readData(tcp_start+8, &newseq, 4);
        newseq = ntohl(newseq);
        newseq++;
        newseq = htonl(newseq);

        uint32_t newack;
        packet.readData(tcp_start+4, &newack, 4);
        newack = ntohl(newack);
        newack++;
        newack = htonl(newack);

        newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
        newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


        uint16_t buf1 = 0;
        buf1 += 5 << 12; 
        buf1 +=  1 << 4; //ACK
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

        it->state = SocketState::CLOSING;
        sendPacket("IPv4", std::move(newPacket));

        if(it->readWaiting){
          size_t temp = it->readbuffersize;
          for(int i=0; i < it->readbuffersize; i++){
            uint8_t a = it->readbuffer->front();
            memcpy((it->wait.buf+i), &a, 1);
            it->readbuffer->pop_front();
          }
          it->readbuffersize = 0;
          it->readWaiting = false;
          returnSystemCall(it->wait.syscallUUID, temp);
        }


      }else if(it->state == FIN_WAIT2){
        int tcp_start = 34;
        int ip_start = 14;

        Packet newPacket(54);
        newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
        newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
        newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
        newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);

        uint32_t newseq;
        packet.readData(tcp_start+8, &newseq, 4);

        uint32_t newack;
        packet.readData(tcp_start+4, &newack, 4);
        newack = ntohl(newack);
        newack++;
        newack = htonl(newack);

        newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
        newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


        uint16_t buf1 = 0;
        buf1 += 5 << 12; 
        buf1 +=  1 << 4; //ACK
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

        sendPacket("IPv4", std::move(newPacket));

        it->state = SocketState::TIME_WAIT;
        Time twomsl = E::TimeUtil::makeTime(5, E::TimeUtil::stringToTimeUnit("sec"));
        addTimer((Socket *) &(*it), twomsl);

      
      }else if(it->state == SocketState::ESTABLISHED){
        int tcp_start = 34;
        int ip_start = 14;

        uint32_t seqcheck;
        packet.readData(tcp_start+4, &seqcheck, 4);
        seqcheck = ntohl(seqcheck);

        bool properpacket = true;

        std::list<packetdata>::iterator find;
        for(find = it->retransmit->begin(); find != it->retransmit->end(); find++){
          if(find->state == PacketState::ACK){
            if(seqcheck != find->ack){
              Packet synPacket = find->packetlist->front();
              this->sendPacket("IPv4", std::move(synPacket));
              properpacket = false;
              break;
            }else{
              it->retransmit->erase(find);
              break;
            }
          }
        }
        
        if(properpacket){
          Packet newPacket(54);
          newPacket.writeData(ip_start + 12, (uint8_t*)&it->addr.sin_addr.s_addr, 4);
          newPacket.writeData(ip_start + 16, (uint8_t*)&it->dstaddr.sin_addr.s_addr, 4);
          newPacket.writeData(tcp_start, (uint8_t*)&it->addr.sin_port, 2);
          newPacket.writeData(tcp_start+2, (uint8_t*)&it->dstaddr.sin_port, 2);

          uint32_t newseq;
          packet.readData(tcp_start+8, &newseq, 4);

          uint32_t newack;
          packet.readData(tcp_start+4, &newack, 4);
          newack = ntohl(newack);
          newack++;
          newack = htonl(newack);

          newPacket.writeData(tcp_start+4, (uint8_t*)&newseq, 4); //seq
          newPacket.writeData(tcp_start+8, (uint8_t*)&newack, 4); //ack


          uint16_t buf1 = 0;
          buf1 += 5 << 12; 
          buf1 +=  1 << 4; //ACK
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

          it->state = SocketState::CLOSE_WAIT;
          it->lastsendSeq = ntohl(newseq);
          it->lastsendAck = ntohl(newack);

          if(it->readWaiting){
            size_t temp = it->readbuffersize;
            for(int i=0; i < it->readbuffersize; i++){
              uint8_t a = it->readbuffer->front();
              memcpy((it->wait.buf+i), &a, 1);
              it->readbuffer->pop_front();
            }
            it->readbuffersize = 0;
            it->readWaiting = false;
            returnSystemCall(it->wait.syscallUUID, temp);
          }

          sendPacket("IPv4", std::move(newPacket));
        }
      }
    }
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  struct Socket *a;
  a = std::any_cast<Socket *> (payload);
  
  if(a->state == SocketState::TIME_WAIT){
    a->state = SocketState::CLOSED;
    UUID closeUUID;

    std::list<Socket>::iterator it;
    struct Socket *tar;
    for(it = socketList.begin(); it!= socketList.end(); it++){
      if(it->fd == a->fd && it->pid == a->pid && it->state == SocketState::CLOSED){

        this->removeFileDescriptor(it->pid, it->fd);
        closeUUID = it->closesyscall;
        socketList.erase(it);
        break;
      }
    }
    this->returnSystemCall(closeUUID, 0);
  }else if(a->state == SocketState::SYN_SENT){


    std::list<packetdata>::iterator it;
    for(it = a->retransmit->begin(); it != a->retransmit->end(); it++){
      if(it->state == PacketState::SYN){
        Packet synPacket = it->packetlist->front();
        this->sendPacket("IPv4", std::move(synPacket));
        it->sendTime = getCurrentTime();
        Time retrans = E::TimeUtil::makeTime(a->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
        it->timersyscall = addTimer(a, retrans);
      }
    }
  }else if(a->state == SocketState::SYN_RCVD){
    std::list<packetdata>::iterator it;
    for(it = a->retransmit->begin(); it != a->retransmit->end(); it++){
      if(it->state == PacketState::SYNACK){
        Packet synPacket = it->packetlist->front();
        this->sendPacket("IPv4", std::move(synPacket));
        it->sendTime = getCurrentTime();
        Time retrans = E::TimeUtil::makeTime(a->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
        it->timersyscall = addTimer(a, retrans);
      }
    }
  }else if(a->state == SocketState::ESTABLISHED || a->state == SocketState::CLOSE_WAIT || a->state == SocketState::FIN_WAIT1){
    std::list<packetdata>::iterator it;
    for(it = a->retransmit->begin(); it != a->retransmit->end(); it++){
      if(it->state == PacketState::ACK){
        Packet synPacket = it->packetlist->front();
        this->sendPacket("IPv4", std::move(synPacket));
        it->sendTime = getCurrentTime();
        Time retrans = E::TimeUtil::makeTime(a->TimeoutInterval / 1000000, E::TimeUtil::stringToTimeUnit("msec"));
        it->timersyscall = addTimer(a, retrans);
        break;
      }
    }
  }
}

} // namespace E
