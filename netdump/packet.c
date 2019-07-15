#include "packet.h"

void set_header(Packet *header){}

//This should be called decode. Section 5.2 Pages 98-100.
void print_packet_header(const u_char *packet){
  currSession.broadcast_packets_total++;                                                              
  char *PACKET_PRINT_FORMAT_IPV6 = "%s = %02x:%02x:%02x:%02x:%02x:%02x\n";                          
  int i = 0;                                                                                        
  /*Print the Addresses */                                                                          
  char *dst_addr = "DEST Address";//0-5                                       
  char *src_addr = "SRC Address ";//6-10
  printf(PACKET_PRINT_FORMAT_IPV6, dst_addr, packet[i++], packet[i++],
	 packet[i++], packet[i++], packet[i++], packet[i++]);                                       
  printf(PACKET_PRINT_FORMAT_IPV6, src_addr, packet[i++], packet[i++],
	 packet[i++], packet[i++], packet[i++], packet[i++]);                                       
                                                                                                  
  /*Print the Type/Length field */                                                                  
  //If the Type/Length field is at least 1536 (0x600) then it is a protocol type.                   
  //Otherwise it is a length                                                                        
  uint16_t type_or_length = ((packet[i++] << 8) +  packet[i++]);//Or 12 
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
      decode_IP_header(packet + 14);
    }
    else if(type_or_length == ARP){
      printf("Payload = ARP\n");                                                                    
      currSession.arp_packets_total++; 
      decode_ARP_packet(packet);                                 
      //Call function that prints out ARP                                                           
    }                                                              
    else if(type_or_length == IPv6 ){                                                               
      printf("Payload = IPv6\n");                                                                   
      //increment this?                                                                             
    }else{                                                        
      //still don't know what 0x9000 is                                                             
      //0x7bda,                                                                                     
      //0x2715,                                                                                     
      //0x1baa,                                                                                     
      //0x1856,                                                                                     
    }                                                                                               
  }     
}

//might run with sudo ./netdump arp -a
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
  printf("Hardware Length: %d\n", hw_len);                                                            
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

//"Remove" first 14 bits. Fixed Header that is 20 bytes long
void decode_IP_header(const u_char *packet){   
  printf("IP Packet Header::\n");
  //version 4 bits: IPv(4/6).
  uint8_t version;
  version = ((packet[0] & 0xF0) >> 4); //first part should negate the last 4, then remove them
  printf("Version: %u\n", version); 
  //Header length 4 bits: 4-byte words (default is 5)
  uint8_t header_len;
  header_len = ((packet[0] & 0x0F) * 4);
  printf("Header length:%u\n", header_len);

  uint8_t service_type;
  service_type = packet[1];
  printf("Service Type: %u \n", service_type);//Usually this is all 0
  uint16_t length;
  length = packet[2] * 256 + packet[3];
  printf("Length of the Payload: %u\n", length);
  //Identifier 16 bits: unique id each one. used for reassembley
  uint16_t identifier;
  identifier = packet[4] * 256 + packet[5];
  printf("Identifier: %u\n", identifier);
  //Flags 3 bits. first is reserved & set to 0.                                                     
  //     D = 1 = don't frag                         
  //     M =1, more data, =0, last packet
  uint8_t flag;//3 freaking bits. [x][y][z]
  //offset(13bits): indicate where the frag should be placed in reassembly buffer
  flag = (packet[6] >>  5); //Really gottta double check this stuff
  printf("Flag: %u %u %u\n", (flag >> 2), ((flag >> 1) & 0x01), (flag  & 0x01));
  uint16_t offset;//13 bits, number of #8 bytes
  //make room for p[7]. Then remvoe the first 3 bits. THEN add p7.
  offset = (((packet[6] << 8) & 0x1F) + packet[7]);
  printf("Offset = %u\n", offset);
  uint8_t TTL;
  TTL = packet[8];
  printf("TTL: %u\n", TTL);

  //Gateway (3), Stream(5), Exterior Gateway(8), private interrori gateay(9)
  //Network voice (11), Host Monitoring (20), Reliable (27), 22, 28, 30, 61
  uint8_t ICMP = 1;
  uint8_t TCP = 6;
  uint8_t UDP = 17;

  uint8_t protocol;
  protocol = packet[9];
  printf("Protocol: %u\n", protocol);
  
  //checksum 16bits: used for err detections
  uint16_t checksum;
  checksum = packet[10] * 256 + packet[11];
  printf("Checksum: %u\n", checksum);
  printf("Src IP Address %u.%u.%u.%u\n", packet[12], packet[13], packet[14], packet[15]);
  printf("Dst IP Address %u.%u.%u.%u\n", packet[16], packet[17], packet[18], packet[19]);

  if(protocol == ICMP){
    currSession.icmp_packets_total++;
    decode_ICMP_header(packet + header_len);
  }
  else if(protocol == TCP){
    printf("Protocol is TCP\n");
    currSession.tcp_packets_total++;
    decode_TCP_header(packet + header_len);
  }
  else if(protocol == UDP){
    printf("Protocol is UDP\n");
    currSession.udp_packets_total++;
  }else{
    printf("Not yet mapped Protocol number %u\n", protocol);
  }
}

  //only give this packet the portion it needs
void decode_ICMP_header(const u_char *packet){
  //TODO:
  printf("Protocol: ICMP::\n");
  //starts after the IP header.                                                                     
  uint8_t type = packet[0];
  uint8_t code = packet[1];
  uint16_t checksum = packet[2] * 256 + packet[3];
  uint32_t original_timestamp = ((
				  ((
				   ((
				     packet[4] << 8) + packet[5])
				   << 8) + packet[6])
				  << 8) + packet[7]);
  uint32_t receive_timestamp = ((
				 ((
				   ((
				     packet[8] << 8) + packet[9])
				   << 8) + packet[10])
				 << 8) + packet[11]);
  uint32_t transmit_timestamp = ((
				  ((
				    ((
				      packet[12] << 8) + packet[13])
				    << 8) + packet[14])
				  << 8) + packet[15]);
  printf("Type: %u, Code: %u\n", type, code);
  printf("Checksum: %u\n", checksum);
  
  if(type == 0 && code == 0){
    printf("\tICMP ECHO Reply\n");
  }
  else if(type == 8 && code == 0){
    printf("\tICMP ECHO Request\n");
  }
  else if(type == 13 && code == 0){
    printf("\tTimestamp request\n");
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

  //Time stuff only prints here
  if(type == 13 || type == 14){
    printf("Original timestamp:   %u\n", original_timestamp);
    printf("Receive timestamp:    %u\n", receive_timestamp);
    printf("Transmit timestamp:   %u\n", transmit_timestamp); 
  }                      
}

void decode_TCP_header(const u_char *packet){

  uint16_t src_port_num;
  src_port_num = ((packet[0] << 8) + packet[1]);
  printf("Source Port Num: %u\n", src_port_num);
  uint16_t dst_port_num;
  dst_port_num = ((packet[2] << 8) + packet[3]);
  printf("Destination Porn Num: %u\n", dst_port_num);
  uint32_t seq_num;
  seq_num = ((
	      ((
		((
		  packet[4] << 8) + packet[5])
		<< 8) + packet[6])
	      << 8) + packet[7]);
  printf("Sequence Num: %u\n", seq_num);
  uint32_t ack_num;
  ack_num = ((
	      ((
		((
		  packet[8] << 8) + packet[9])
		<< 8) + packet[10])
	      << 8) + packet[11]);
  printf("Acknowledge Num: %u\n", ack_num);
  uint8_t hdr_len;//4 bits
  hdr_len = (packet[12] & 0xF0) * 4; // times 4?
  printf("Header Length: %u\n", hdr_len);
  uint8_t reserved;//6 bits
  reserved = ((packet[12] & 0x3F) >> 2);
  printf("Reserved: %u\n", reserved);
  uint8_t flags;//6
  flags = (packet[13] & 0x3F);
  printf("Flags: %u\n", flags);
  printf("Flag\t          Function          \t Value \n");
  printf("URG \t Packet Contains Urgent Data \t   %u\n", flags >> 5);
  printf("ACK \t      Ack Num Is Valid  \t   %u\n", flags >> 4 & 0x01);
  printf("PSH \tData Should be pushed to Appl\t   %u\n", flags >> 3 & 0x01);
  printf("RST \t         Reset Packet       \t   %u\n", flags >> 2 & 0x01);
  printf("SYN \t      Synchronize Packet    \t   %u\n", flags >> 1 & 0x01);
  printf("FIN \t       Finish Packet        \t   %u\n", flags & 0x01);

  uint16_t window_size;
  window_size = (packet[14] << 8 + packet[15]);
  printf("Window size: %u\n", window_size);
  uint16_t checksum;
  checksum = ((packet[16] << 8) + packet[17]);
  printf("Checksum: %u\n", checksum);
  uint16_t urgent_pointer;
  urgent_pointer = ((packet[18] << 8) + packet[19]);
  printf("Urgent Pointer: %u\n", urgent_pointer);
  
  int i = 0;
  int diff = 0;
  if(hdr_len == 0){
    hdr_len = 40;
  }
  diff = hdr_len - 20;
  int offset = 20;
  printf("Options--- \n");
  for(i = 0; i < diff; i++){
    printf("%x", packet[i + offset]);
  }
  printf("\n");
  
}
