#ifndef PACKET_H
# define PACKET_H

#include <stdio.h>
#include <stdint.h>

/* Define common numbers here*/

typedef struct{
  const u_char *raw_data;
  u_char *dest_addr;
  u_char *src_addr;
}Info;

typedef struct{
  Info contents;
  uint16_t hw_type;
  uint16_t protocol_type;
  uint8_t hw_len;
  uint8_t protocol_len;
  uint16_t operation;
  //Don't know if I can do the others yet
}ARP;

typedef struct{
  //version
  //header length
  uint8_t type_of_service;
  uint8_t length;
  uint16_t identifier;
  uint8_t TTL;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_ip_addr;
  uint32_t dest_ip_addr;
  //options
  //data
}IP;


#endif
