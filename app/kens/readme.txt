#README for PA2

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