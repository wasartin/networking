/*
 * Packet Sniffer 
 * ---------------
 */
#define RETSIGTYPE void

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif
char cpre580f98[] = "netdump";//not sure yet

//Helper method that prints out the type of the packet.
void print_packet_header(const u_char* packet);
void decode_ARP_packet(const u_char *packet);//6a
void decode_IP_header(const u_char *packet);//6b
void decode_ICMP_header(const u_char *packet);//6c
void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packet_type; //ICMP(1), UDP(17), TCP(6) etc.

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int); //Berkey packet Filter

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Global Variables And Declarations */
int num_broadcast_packets = 0;
int num_ip_packets = 0;
int num_arp_packets = 0;
int num_icmp_packets = 0;

/* Length of saved portion of packet. */
int snaplen = 1500;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int main(int argc, char **argv) {
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	int run_ad_infinitum = -1;
	cnt = run_ad_infinitum;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1) {
	  switch (i) {
	  case 'p':
	    pflag = 1;
	    break;
	  case 'a':
	    aflag = 1;
	    break;
	  case '?':
	  default:
	    done = 1;
	    break;
	  }
	  if (done){
	    break;
	  }
	}
	if (argc > (optind)){
	  cmdbuf = copy_argv(&argv[optind]);
	} 
	else {
	  cmdbuf = "";
	}

	if (device == NULL) {
	  device = pcap_lookupdev(ebuf);
	  if (device == NULL){
	    error("%s", ebuf);
	  }
	}

	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL){
	  error("%s", ebuf);
	}
	i = pcap_snapshot(pd);
	if (snaplen < i) {
	  warning("snaplen raised from %d to %d", snaplen, i);
	  snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
	  localnet = 0;
	  netmask = 0;
	  warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());
	
	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0){
	  error("%s", pcap_geterr(pd));
	}
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL){
	  (void)setsignal(SIGHUP, oldhandler);
	}
	if (pcap_setfilter(pd, &fcode) < 0){
	  error("%s", pcap_geterr(pd));
	}
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);

	/*pd = the packet
	* cnt = number of packets to run (-1 means infinity)
	* raw_print = pcap handler callback
	* pcap_userdata = 
	*/
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
	  (void)fprintf(stderr, "%s: pcap_loop: %s\n",
			program_name, pcap_geterr(pd));
	  exit(1);
	}
	pcap_close(pd);

	/** TODO: DELETE THIS. THIS IS ONLY HERE FOR DEBUGGING SMALL RUNS */
	//printf("Number of Broadcast packets received = %d\n", num_broadcast_packets);
	//printf("Number of IP packets received = %d\n", num_ip_packets);
	//printf("Number of ARP packets received = %d\n", num_arp_packets);
	exit(0);
}

/*Programin is ending,  routine is executed on exit */
void program_ending(int signo) {
	struct pcap_stat stat;
	
	if (pd != NULL && pcap_file(pd) == NULL) {
	  (void)fflush(stdout);
	  putc('\n', stderr);
	  if (pcap_stats(pd, &stat) < 0){
	    (void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
	  }
	  else {
	    (void)fprintf(stderr, "%d packets received by filter\n",
			  stat.ps_recv);
	    (void)fprintf(stderr, "%d packets dropped by kernel\n",
			  stat.ps_drop);
	    
	    (void)fprintf(stderr, "Number of Broadcast Packets = %d\n",
			  num_broadcast_packets);
	    (void)fprintf(stderr, "Number of IP Packets = %d\n",
			  num_ip_packets);
	    (void)fprintf(stderr, "Number of ARP Packets = %d\n",
			  num_arp_packets);
	    (void)fprintf(stderr, "Number of ICMP Packets = %d\n",
			  num_icmp_packets);    	    
	  }
	}
	exit(0);
}

/* Like default_print() but data need not be aligned */
void default_print_unaligned(register const u_char *cp, register u_int length) { 
  register u_int i, s; //register means it will be used a lot, it is a tip to the compiler
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
	  if ((i++ % 8) == 0){
	    (void)printf("\n\t\t\t");
	  }
	  s = *cp++;
	  (void)printf (" %02x%02x ", s, *cp++);// This is printing two sets of info. s will jump another spot, and this will print the next two things	
	}
	if (length & 1) {
	  if ((i % 8) == 0){
	    (void)printf("\n\t\t\t");
	  }
	  (void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void default_print(register const u_char *bp, register u_int length) {
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
	  if ((i++ % 8) == 0){
	    (void)printf("\n\t");
	  }
	  (void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
	  if ((i % 8) == 0){
		(void)printf("\n\t");
	  }
	  (void)printf(" %02x", *(u_char *)sp);
	}
}

/*
 * Print the ethernet header of the packet
 *
 */
void print_packet_header(const u_char* packet){
  num_broadcast_packets++;
  char *PACKET_PRINT_FORMAT_IPV6 = "%s = %02x:%02x:%02x:%02x:%02x:%02x\n";
 
  /*Print the Addresses */
  char *dst_addr = "DEST Address";
  char *src_addr = "SRC Address ";
  printf(PACKET_PRINT_FORMAT_IPV6, dst_addr, packet[0], packet[1],\
	 packet[2], packet[3], packet[4], packet[5]);
  printf(PACKET_PRINT_FORMAT_IPV6, src_addr, packet[6], packet[7],\
	 packet[8], packet[9], packet[10], packet[11]);

  /*Print the Type/Length field */
  //If the Type/Length field is at least 1536 (0x600) then it is a protocol type.
  //Otherwise it is a length
  uint16_t type_or_length = packet[12]*256 + packet[13];
  uint16_t cut_off = 0x0600;
  if(type_or_length >= cut_off){
    printf("Type = 0x%04x, ", type_or_length);
    
    uint16_t IP = 0x800;
    uint16_t ARP = 0x806;
    uint16_t IPv6 = 0x86DD;
    /*
    if(type_or_length == IP){
      printf("Payload = IP\n");
      num_ip_packets++;
    }
    */
    if(type_or_length == ARP){
      printf("Payload = ARP\n");
      num_arp_packets++;
      //first try putting the whole thing ing
      decode_ARP_packet(packet);
      //Call function that prints out ARP
    }
    /*
    else if(type_or_length == IPv6 ){
      printf("Payload = IPv6\n");
      //increment this?
    }else{
      printf("Payload is not yet mapped\n");
      //still don't know what 0x9000 is
    }
    */
    
  }else{
    printf("Length = %0d\n", packet[12]);
  }  
}

/*
 * This is used as the callback function for pcap_loop. 
 * it is called every time a packet is received. 
 * caplen is the length of the ethernet packet
 * character array p, which is the packet p[0] DEST hardware address
 */
void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
  u_int length = h->len;
  u_int caplen = h->caplen; //the length of the ethernet packet

  printf("\n\t +++++++++++[START OF PACKET]+++++++++++\n");
    
  print_packet_header(p);
  //Printing the packet
  default_print(p, caplen);
  putchar('\n');  
  printf("\n\t ------------[END OF PACKET]------------\n");
}

/* Decode and print out the ARP Packet */
void decode_ARP_packet(const u_char *packet_data){
  //I think things start at p[14]?
  printf("Arp Packet");
  //ARP REPLY
  //ARP REQUEST
  int i = 14;
  
  uint16_t hw_type = packet_data[i++] * 256 + packet_data[i++];
  uint16_t protocol_type = packet_data[i++] * packet_data[i++];
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
    printf("ARP Request\n");
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

/* Decode and print out the IP Header, the rest can be printed normally */ 
void decode_IP_header(const u_char *packet){
  //TODO: (packet[14])?
  printf("IP Packet Header::\n");
  //Decode
 
  //print
  //version 4 bits: IPv(4/6).
  printf("Version: %b", (packet[14] >> 4));
  //Header length 4 bits: 4-byte words (default is 5)
  printf("Header length:%b \n", packet[15]);
  //Type of service 8 bits: not generally used, usually set to all 0
  //Length 16bits. length of the payload in bytes
  //Identifier 16 bits: unique id each one. used for reassembley
  //Flags 3 bits. first is reserved & set to 0.
  //     2nd is D flag (don't fragment). 1 is don't frag.
  //     3rd is M flag. (more). if 1 then there is another. if 0 then it's done
  //offset(13bits): indicate where the frag should be placed in reassembly buffer
  //TTL 8bits:
  //Protocol 8bits: indicates upper layer protocol that will handle packet.
  //     1 for ICMP, 6 for TCP, 17 for UDP
  //checksum 16bits: used for err detections
  //src IP addr (32 bits)
  //dest IP add (32 bits)
  //options (variable) 
  //data (variable). 65,536 - header length. 
}

/* Decode and print out the ICMP */
void decode_ICMP_header(const u_char *packet){
  //TODO:
  //starts after the IP header.
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
  //Checksum(16bits)
  //Parameter(32bits): depends on type
  //info(32bits)
  
}




