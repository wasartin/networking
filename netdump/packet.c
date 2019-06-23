#include "packet.h"

void set_header(Packet *header){}

void print_packet_header(const u_char *packet){
  currSession.broadcast_packets_total++;                                                              
  char *PACKET_PRINT_FORMAT_IPV6 = "%s = %02x:%02x:%02x:%02x:%02x:%02x\n";                          
  int i = 0;                                                                                        
  /*Print the Addresses */                                                                          
  char *dst_addr = "DEST Address";                                                                  
  char *src_addr = "SRC Address ";                                                                  
  printf(PACKET_PRINT_FORMAT_IPV6, dst_addr, packet[i++], packet[i++],
	 packet[i++], packet[i++], packet[i++], packet[i++]);                                       
  printf(PACKET_PRINT_FORMAT_IPV6, src_addr, packet[i++], packet[i++],
	 packet[i++], packet[i++], packet[i++], packet[i++]);                                       
                                                                                                    
  /*Print the Type/Length field */                                                                  
  //If the Type/Length field is at least 1536 (0x600) then it is a protocol type.                   
  //Otherwise it is a length                                                                        
  uint16_t type_or_length = packet[i++]*256 + packet[i++];                                          
  uint16_t cut_off = 0x0600;                                                                        
  if(type_or_length < cut_off){                                                                     
    printf("Length = %0d\n", packet[12]);                                                           
  }else{//Protocol Type                                                                             
    printf("Type = 0x%04x, ", type_or_length);                                                      
           
    uint16_t IP = 0x800;                                                                            
    uint16_t ARP = 0x806;                                                                           
    uint16_t IPv6 = 0x86DD; 
    if(type_or_length == IP){                                                                       
      printf("Payload = IP\n");                                                                     
      currSession.ip_packets_total++;
    }
    if(type_or_length == ARP){                                                                      
      printf("Payload = ARP\n");                                                                    
      currSession.arp_packets_total++; 
      decode_ARP_packet(packet);                                                                    
      //Call function that prints out ARP                                                           
    }                                                              
    else if(type_or_length == IPv6 ){                                                               
      printf("Payload = IPv6\n");                                                                   
      //increment this?                                                                             
    }else{                                                                                          
      printf("Payload is not yet mapped\n");                                                        
      //still don't know what 0x9000 is                                                             
      //0x7bda,                                                                                     
      //0x2715,                                                                                     
      //0x1baa,                                                                                     
      //0x1856,                                                                                     
    }                                                                                               
  }     
}

void decode_ARP_packet(const u_char *packet_data){
  printf("Arp Packet");
  int i = 14;                                                                                       
                                                                                                    
  uint16_t hw_type = packet_data[i++] * 256 + packet_data[i++];                                     
  uint16_t protocol_type = packet_data[i++] *256 + packet_data[i++];
  uint8_t hw_len = packet_data[i++];                                                                
  uint8_t protocol_len = packet_data[i++];                                                          
  uint16_t operation = packet_data[i++] * 256 + packet_data[i++];                                   
               
  u_char sender_hw_addr[hw_len];                                                                    
  int h = 0;                                                                                        
  for(h = 0; h < hw_len; h++){                                          
    sender_hw_addr[h] = packet_data[i++];                                                           
  }                                                                                                 
  //if IPv4, then it is 4 bytes, so IPv6 is 6 bytes?                                                
  uint8_t sender_protocol_addr[protocol_len];                                                       
  int p = 0;                                                                                        
  for(p = 0; p < protocol_len; p++){                                                                
    sender_protocol_addr[p] = packet_data[i++];                                                     
  }                                                                                                 
  u_char target_hw_addr[hw_len];                                                                    
  for(h = 0; h < hw_len; h++){                                                                      
    target_hw_addr[h] = packet_data[i++];                                                           
  }                                                                                                 
  uint8_t target_protocol_addr[protocol_len];                                                       
  for(p = 0; p < protocol_len; p++){                                                                
    target_protocol_addr[p] = packet_data[i++];                                                     
  }                                                                                                 
                                                                                                    
  printf("Hardware type: %u\n", hw_type);                                                           
  printf("Protocol Type: %u\n", protocol_type);                                                     
  printf("Hardware Length: %d", hw_len);                                                            
  printf("Protocol Length: %d\n", protocol_len);                                                    
  printf("Operation: %u\n", operation);                                                             
  if(operation == 1){                                                                               
    printf("ARP Request\n");                                                                        
  }                                                                                                 
  else if(operation == 2){                                                                          
    printf("ARP Reply\n");                                                                          
  }else {                                                                                           
    printf("Error : Unknown Arp Operation");                                                        
  }                                                                                                 
  //This is where things can get weird. Got to print out all the things with                        
  //  variables lengths. This would probably be better to put into a method                         
  //IPv4 does xxx.xxx.xxx.xxx. || IPv6 does xx:xx:xx:xx:                                            
  //Hardware addresses use the :, but I will diff between IPv later.                                
  printf("Sender Hardware Address: ");                                                              
  for(h = 0; h < hw_len; h++){//There has to be a better way to do this                             
    printf("%02x", sender_hw_addr[h]);                                                              
    printf((h + 1 < hw_len)? ":" : "\n");                                                           
  }                                   
  printf("Sender Protocol Address: ");//TODO: Look in printing diff of IPv4/6                       
  for(p = 0; p < protocol_len; p++){                                                                
    printf("%d", sender_protocol_addr[p]);                                                          
    printf((p + 1 < protocol_len)? "." : "\n");                                                     
  }                                                                                                 
  printf("Target Hardware Address: ");                                                              
  for(h = 0; h < hw_len; h++){                                                                      
    printf("%02x", target_hw_addr[h]);                                                              
    printf((h + 1 < hw_len)? ":" : "\n");                                                           
  }                                                                                                 
  printf("Target Protocol Address: ");                                                              
  for(p = 0; p < protocol_len; p++){                                                                
    printf("%d", target_protocol_addr[p]);//TODO: Look in printing diff of IPv4/6                   
    printf((p + 1 < protocol_len)? "." : "\n");                                                     
  }                                                                                                 
  
}
void decode_IP_header(const u_char *packet){   
  printf("IP Packet Header::\n");                                                            
  //Decode                                                                                          
  int i = 14;
  //print                                                                                           
  //version 4 bits: IPv(4/6).
  uint8_t version;
  version = ((packet[14] & 0xF0) >> 4); //first part should negate the last 4, then remove them
  printf("Version: %u", ); 
  //Header length 4 bits: 4-byte words (default is 5)
  uint8_t header_len;
  header_len = ((packet[14] & 0x0F) << 4);
  printf("Header length:%u \n", header_len);

  uint8_t service_type;
  service_type = packet[15];
  printf("Service Type: %u \n", service_type);//Usually this is all 0

  uint16_t length;
  length = packet[16] * 256 + packet[17];
  printf("Length of the Payload: %u\n", length);
  //Identifier 16 bits: unique id each one. used for reassembley
  uint16_t identifier;
  identifier = packet[17] * 256 + packet[18];
  printf("Identifier: %u\n", identifier);
  //Flags 3 bits. first is reserved & set to 0.                                                     
  //     2nd is D flag (don't fragment). 1 is don't frag.                                           
  //     3rd is M flag. (more). if 1 then there is another. if 0 then it's done
  uint8_t flag;//3 freaking bits. [x][y][z]
  //offset(13bits): indicate where the frag should be placed in reassembly buffer
  flag = (((packet[18] * 256 + packet[19]) & 0xFFF8) << 5); //Really gottta double check this stuff
  printf("Flag: %u %u %u\n", (flag >> 2), ((flag >> 1) & 0x01), ((flag << 2) & 0x30));
  uint16_t offset;//13 bits
  offset = packet[19] * 256 + packet[20];
  printf("Offset = %u\n", offset);
  uint8_t TTL;
  TTL = packet[20];
  printf("TTL: %u\n", TTL);
  //Protocol 8bits: indicates upper layer protocol that will handle packet.                         
  //     1 for ICMP, 6 for TCP, 17 for UDP
  uint8_t ICMP = 1;
  uint8_T TCP = 8;
  uint8_t UDP = 17;
  uint8_t protocol;
  protocol = packet[21];
  printf("Protocol: %u", protocol);
  char *result;
  switch(protocol){
  case ICMP:
    result = "ICMP";
    break;
  case TCP:
    result = "TCP";
    break;
  case UDP:
    result = "UDP";
    break;
  default:
    result = "UNKNOWN";
    break;
  }
  printf(": %s\n", result);
  //checksum 16bits: used for err detections
  uint16_t checksum;
  checksum = packet[22] * 256 + packet[23];
  printf("Checksum: %u\n", checksum);

  const char *ADDR_FORMAT = "%04x:%04x:%04x:%04x\n";
  printf("Src IP Address %s", ADDR_FORMAT, packet[23]. packet[24], packet[25], packet[26]);
  printf("Dst IP Address %s", ADDR_FORMAT, packet[27]. packet[28], packet[29], packet[30]);

  //TODO figure out the length part
  //options (variable)                                                                              
  //data (variable). 65,536 - header length.

  //TODO: Call ICMP Header

  
}

  //only give this packet the portion it needs
void decde_ICMP_header(const u_char *packet){
  //TODO:
  printf("ICMP::\n");
  //starts after the IP header.                                                                     
  uint8_t type = packet[0];
  uint8_t code = packet[1];
  
  printf("Type: %u, Code: %u", type, code);
  if(type == 0 && code == 0){
    printf("\tICMP ECHO Reply\n");
  }
  else if(type == 8 && code == 0){
    printf("\tICMP ECHO Request\n");
  }
  else if(type == 14 && code ==0){
    printf("\tTimestamp reply\n");
  }
  else if(type == 3 && (code > 0 && code <= 15)){
    printf("\tDest unreachable\n");
  }
  else if(type == 11 && code <= 1){
    printf("\tTime exeeced\n");
  }
  else if(type == 5 & code <= 3){
    printf("Redirection\n");
  }else{
    printf("Don't know yet\n");
  }
  
  uint16_t checksum = packet[2] * 256 + packet[3];
  printf("Checksum: %u\n", checksum);
  
  //Type (8bits)                                                                                    
  //    0 -> Echo reply ||                                                                          
  //    3 -> Err, dest unreachable                                                                  
  //    5 -> Redirection                                                                            
  //    8 -> echo request                                                                           
  //   11 -> Time exceeded                                                                          
  //   13 -> Timestamp req                                                                          
  //   14 -> Timestampe reply                                                                       
  //    if type = 0 then ICMP ECHO REPLY                                                            
  //Code(8bits)                                                                                     
  //    0 -> Network-based redirect                                                                 
  //    1 -> host-based redirect                                                                    
  //    2 -> Network-based redirect of the type of service specified                                
  //    3 -> Host-based redirect "                                                                  
  //TODO: Figure out rest & timestamp                                                                        
                      
}

