/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <E/E_TimeUtil.hpp>

#include "RoutingAssignment.hpp"

#include <inttypes.h>


namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {
        this->host = &host;
      }

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {
  for(size_t port_num = 0; port_num < host->getPortCount(); port_num ++ ){

    Packet newPacket(66);

    int rip_start = 42;
    int udp_start = 34;
    int ip_start = 14;
    
    ipv4_t dstip;
    for(int i=0; i<4; i++){
      dstip[i] = (uint8_t)0xff;
    }

    uint32_t tmp = 0xff | (0xff << 8) | (0xff << 16) | (0xff << 24);
    
    std::optional<ipv4_t> srcip = getIPAddr(port_num); // retrieve the source IP address
    ipv4_t t = *srcip;
    uint32_t tmp2 = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);
    
    struct rip_entry_t entry;
    entry.address_family = 2;
    entry.zero_1 = 0;
    entry.zero_2 = 0;
    entry.zero_3 = 0;
    entry.metric = 0;
    entry.ip_addr = tmp2;
    ripList.push_back(entry);

    newPacket.writeData(ip_start + 12, (uint8_t*)&tmp2, 4);
    newPacket.writeData(ip_start + 16, (uint8_t*)&tmp, 4);

    uint16_t port = 520;
    port = htons(port);
    newPacket.writeData(udp_start, (uint8_t*)&port, 2);
    newPacket.writeData(udp_start+2, (uint8_t*)&port, 2);
    
    uint16_t buf1 = 32;
    buf1 = htons(buf1);
    newPacket.writeData(udp_start+4, (uint8_t*)&buf1, 2);
    buf1 = 0;
    newPacket.writeData(udp_start+6, (uint8_t*)&buf1, 2);

    uint8_t buf2 = 1;
    newPacket.writeData(rip_start, (uint8_t*)&buf2, 1);

    newPacket.writeData(rip_start+1, (uint8_t*)&buf2, 1);
    newPacket.writeData(rip_start+2, (uint8_t*)&buf1, 2);
    buf1 = 0;
    newPacket.writeData(rip_start+4, (uint8_t*)&buf1, 2);
    buf1 = 0;
    newPacket.writeData(rip_start+6, (uint8_t*)&buf1, 2);

    uint32_t buf3 = 0;
    newPacket.writeData(rip_start+8, (uint8_t*)&buf3, 4);
    newPacket.writeData(rip_start+12, (uint8_t*)&buf3, 4);
    newPacket.writeData(rip_start+16, (uint8_t*)&buf3, 4);
    buf3 = 16;
    buf3 = htonl(buf3);
    newPacket.writeData(rip_start+20, (uint8_t*)&buf3, 4);

    this->sendPacket("IPv4", std::move(newPacket)); 
  }

  Time time = E::TimeUtil::makeTime(30, E::TimeUtil::stringToTimeUnit("sec"));
  addTimer(nullptr, time);
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below

  uint32_t ip = ipv4[0] | (ipv4[1] << 8) | (ipv4[2] << 16) | (ipv4[3] << 24);
  std::list<rip_entry_t>::iterator it;
  
  for(it = ripList.begin(); it != ripList.end(); it++){
    struct rip_entry_t rip = *it;
    if(ip==rip.ip_addr){
      return rip.metric;
    }
  }

  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  int rip_start = 42;
  int udp_start = 34;
  int ip_start = 14;

  uint8_t packet_type;
  packet.readData(rip_start, &packet_type, 1);

  if(packet_type==1){
    //request
    uint32_t srcip;
    uint8_t tmpip[4];
    packet.readData(ip_start + 12, &srcip, 4);
    packet.readData(ip_start + 12, &tmpip, 4);

    ipv4_t ipv4;
    for(int i=0; i<4; i++){
      ipv4[i] = tmpip[i];
    }

    int nicport = getRoutingTable(ipv4); // retrieve NIC port
    std::optional<ipv4_t> srcipv4 = getIPAddr(nicport); // retrieve the source IP address
    ipv4_t t = *srcipv4;

    Packet newPacket(42 + 4 + ripList.size() * 20);

    int rip_start = 42;
    int udp_start = 34;
    int ip_start = 14;

    uint32_t tmp2 = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);

    newPacket.writeData(ip_start + 12, (uint8_t*)&tmp2, 4);
    newPacket.writeData(ip_start + 16, (uint8_t*)&tmpip, 4);

    uint16_t port = 520;
    port = htons(port);
    newPacket.writeData(udp_start, (uint8_t*)&port, 2);
    newPacket.writeData(udp_start+2, (uint8_t*)&port, 2);
    
    // uint16_t buf1 = 32;
    uint16_t buf1 = 8 + 4 + 20 * ripList.size();
    buf1 = htons(buf1);
    newPacket.writeData(udp_start+4, (uint8_t*)&buf1, 2);
    buf1 = 0;
    newPacket.writeData(udp_start+6, (uint8_t*)&buf1, 2);
    
    uint8_t buf2 = 2;
    newPacket.writeData(rip_start, (uint8_t*)&buf2, 1); //command
    buf2 = 1;
    newPacket.writeData(rip_start+1, (uint8_t*)&buf2, 1); // version
    newPacket.writeData(rip_start+2, (uint8_t*)&buf1, 2); // zero
    rip_start += 4;

    std::list<rip_entry_t>::iterator it;
    for(it = ripList.begin(); it != ripList.end(); it++){
      struct rip_entry_t rip = *it;
    
      buf1 = 2;
      buf1 = htons(buf1);
      newPacket.writeData(rip_start+0, (uint8_t*)&buf1, 2); // address family idenfier
      buf1 = 0;
      newPacket.writeData(rip_start+2, (uint8_t*)&buf1, 2); //zero

      uint32_t buf3 = rip.ip_addr;
      // buf3 = htonl(buf3);

      newPacket.writeData(rip_start+4, (uint8_t*)&buf3, 4); //ip address
      buf3 = 0;
      newPacket.writeData(rip_start+8, (uint8_t*)&buf3, 4); //zero
      newPacket.writeData(rip_start+12, (uint8_t*)&buf3, 4); //zero
      buf3 = rip.metric;
      buf3 = htonl(buf3);
      newPacket.writeData(rip_start+16, (uint8_t*)&buf3, 4); //metric

      rip_start += 20;
    }

    this->sendPacket("IPv4", std::move(newPacket));   

  } else if(packet_type==2){
    //response
    size_t packetSize = packet.getSize();
    uint8_t srcip[4];
    packet.readData(ip_start + 12, &srcip, 4);
    
    ipv4_t dstipv4;
    for(int i=0; i<4; i++){
      dstipv4[i] = srcip[i];
    }

    int dst_port = getRoutingTable(dstipv4);
    
    size_t cost = linkCost(dst_port);

    std::optional<ipv4_t> srcipv4 = getIPAddr(dst_port); // retrieve the source IP address
    ipv4_t t = *srcipv4;
    uint32_t myip = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);
    rip_start += 4;
    int rip_num = (packetSize - rip_start) / 20;

    for(int i=0; i<rip_num; i++){
      int offset = rip_start + i * 20;
      uint32_t ip_addr;
      packet.readData(offset + 4, &ip_addr, 4);
      uint8_t buf2[4];
      packet.readData(offset + 16, &buf2, 4);
      int metric = buf2[3];

      uint8_t ip_addr_8[4];
      packet.readData(offset + 4, &ip_addr_8, 4);
      ipv4_t ip_ipv4;
      for(int i=0; i<4; i++){
        ip_ipv4[i] = ip_addr_8[i];
      }

      std::list<rip_entry_t>::iterator it;
      struct rip_entry_t new_rip;
      int status = 0; // 0 : new ip, 1: update dv, 2: nothing
      for(it = ripList.begin(); it != ripList.end(); it++){
        struct rip_entry_t rip = *it;
        if(rip.ip_addr == ip_addr){
          if(rip.metric > metric+cost){
            //should update metric
            new_rip.address_family = rip.address_family;
            new_rip.ip_addr = rip.ip_addr;
            new_rip.zero_1 = rip.zero_1;
            new_rip.zero_2 = rip.zero_2;
            new_rip.zero_3 = rip.zero_3;
            new_rip.metric = metric+cost;
            ripList.erase(it);
            status = 1;
          } else {
            status = 2;
          }
          break;    
        }
      }
      if(status == 1){
        ripList.push_back(new_rip);
      } else if(status == 0){
        //new ip detected
        new_rip.address_family = 2;
        new_rip.zero_1 = 0;
        new_rip.ip_addr = ip_addr;
        new_rip.zero_2 = 0;
        new_rip.zero_3 = 0;
        new_rip.metric = metric + cost;
        ripList.push_back(new_rip);
      }
    }
  }
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;

  for(size_t port_num = 0; port_num < host->getPortCount(); port_num ++ ){

    Packet newPacket(42 + 4 + ripList.size() * 20);

    int rip_start = 42;
    int udp_start = 34;
    int ip_start = 14;
    
    ipv4_t dstip;
    for(int i=0; i<4; i++){
      dstip[i] = (uint8_t)0xff;
    }

    uint32_t tmp = 0xff | (0xff << 8) | (0xff << 16) | (0xff << 24);

    std::optional<ipv4_t> srcip = getIPAddr(port_num); // retrieve the source IP address
    ipv4_t t = *srcip;

    uint32_t tmp2 = t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24);

    newPacket.writeData(ip_start + 12, (uint8_t*)&tmp2, 4);
    newPacket.writeData(ip_start + 16, (uint8_t*)&tmp, 4);

    uint16_t port = 520;
    port = htons(port);
    newPacket.writeData(udp_start, (uint8_t*)&port, 2);
    newPacket.writeData(udp_start+2, (uint8_t*)&port, 2);
    
    uint16_t buf1 = 8 + 4 + 20 * ripList.size();
    buf1 = htons(buf1);
    newPacket.writeData(udp_start+4, (uint8_t*)&buf1, 2);
    buf1 = 0;
    newPacket.writeData(udp_start+6, (uint8_t*)&buf1, 2);
    
    uint8_t buf2 = 2;
    newPacket.writeData(rip_start, (uint8_t*)&buf2, 1); //command
    buf2 = 1;
    newPacket.writeData(rip_start+1, (uint8_t*)&buf2, 1); // version
    newPacket.writeData(rip_start+2, (uint8_t*)&buf1, 2); // zero
    rip_start += 4;

    std::list<rip_entry_t>::iterator it;
    for(it = ripList.begin(); it != ripList.end(); it++){
      struct rip_entry_t rip = *it;
    
      buf1 = 2;
      buf1 = htons(buf1);
      newPacket.writeData(rip_start+0, (uint8_t*)&buf1, 2); // address family idenfier
      buf1 = 0;
      newPacket.writeData(rip_start+2, (uint8_t*)&buf1, 2); //zero

      uint32_t buf3 = rip.ip_addr;

      newPacket.writeData(rip_start+4, (uint8_t*)&buf3, 4); //ip address
      buf3 = 0;
      newPacket.writeData(rip_start+8, (uint8_t*)&buf3, 4); //zero
      newPacket.writeData(rip_start+12, (uint8_t*)&buf3, 4); //zero
      buf3 = rip.metric;
      buf3 = htonl(buf3);
      newPacket.writeData(rip_start+16, (uint8_t*)&buf3, 4); //metric

      rip_start += 20;
    }

    this->sendPacket("IPv4", std::move(newPacket)); 
  }

  Time time = E::TimeUtil::makeTime(30, E::TimeUtil::stringToTimeUnit("sec"));
  addTimer(nullptr, time);
}

} // namespace E
