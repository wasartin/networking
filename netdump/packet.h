#ifndef PACKET_H
# define PACKET_T

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*CONSTANTS */
#define ADDR_LENGTH 6
#define ARP_REQUEST 1
#define ARP_REPLY 2

/* Used to keep information about the current Session*/
typedef struct{
  int broadcast_packets_total;
  int ip_packets_total;
  int arp_packets_total;
  int icmp_packets_total;  
}Session;

typedef struct{
  u_char *raw_data;
  u_int length;
  u_int caplen;
  u_char dest_addr[ADDR_LENGTH];
  u_char src_addr[ADDR_LENGTH];
  uint16_t type_length;
}Packet;

typedef struct{
  Packet info;
  uint16_t hw_type;
  uint16_t protocol_type;
  uint8_t hw_len;
  uint8_t protocol_len;
  uint16_t operation; //if 1 then 
}ARP;

void print_packet_header(const u_char *packet);
void decode_ARP_packet(const u_char *packet_data);//6a
void decode_IP_header(const u_char *packet);//6b
void decde_ICMP_header(const u_char *packet);//6c

#endif
