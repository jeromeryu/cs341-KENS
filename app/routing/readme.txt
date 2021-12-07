#README for PA2, PA3, PA4

# PA2
# 3 extra structs are made
Socket : for socket used in tcp 
Accept : for managing asynchronous in accept syscall and receiving ack packet
Connection : for managing backlog control

# Enum SocketState is made
It holds CLOSED, LISTEN, SYN_RCVD(syn received), SYN_SENT, ESTABLISHED for tracking 3-way handshaking

# 3 lists are used to hold these structs
std::list<Socket> socketList;
std::list<Accept> acceptList;
std::list<Connection> connectionList;

# Each functions for syscall handling are implemented
void syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused, int protocol);
void syscall_close(UUID syscallUUID, int pid, int fd);
void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);


# TCPAssignment::packetArrived function is used for recognizing SYN, SYN+ACK, ACK packets
It is specified in if-else statements in the code.
We checked SYN and ACK bytes to check which type of packet arrived.
SYN -> change socket state to SYN_RCVD and send SYN+ACK packet
SYN+ACK -> change socket state to ESTABLISHED and send ACK packet
ACK -> change socket state to ESTABLISHED

#PA3
# 2 extra structs are made
readwait : buffer for read systemcall in socket
packetdata : save packet data sent from socket. If properly responsed, it will be deleted. If time out, resend.

# 2 additional Enum and edit SocketState
SocketState: added state for closing (including simultaneous closing)
AckPacketState: classify type of received Ack packet
PacketState: classify type of packet sent from socket

# socket
1. 4 way handshaking implemented including simultaneous closing.
2. read, write systemcall implemented.
read : When Ack packet with data received, socket copies data into socket readbuffer. If there exists enough read buffer, copies data to destination and read systemcall returns.
write: When write systemcall issued, socket copies data from source into socket write buffer and write systemcall returns immediatly. Socket checks the write buffer and send Ack packet with data.
3. Unrealiable connection handling implemented.
- check checksum.
- check whether proper response packet arrived and if not, send packet again.
- works well with 3 handshake connection, data transmission inclusing read write systemcall.
4. TimeoutInterval implemented. 

#PA4
Variable ripList is made. It is a list of struct rip_entry_t that holds ip address and metric value of nearby routers. 
ripList is used as distance vector table

# Initialize function
Adds rip_entry_t values of routers that are directly connected to itself with metric value 0.
Sends request packet to all routers that are directly connected, and set timer

# TimerCallback function
If timeout, sends response to all routers that are directly connected, and reset timer

# PacketArrivec function
If a router receives request packet, it sends its dv table via response packet to router that sent request packet.
IF a router receives response packet, it updates its dv table using dv table arrived from response packet and linkCost.

# RipQuery function
It returns metric value in dv table(ripList) if given ip address exists in dv table.