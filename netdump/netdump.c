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

#include "packet.h"
#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

//My global variable. Nothing could go here.
Session currSession = {0, 0, 0, 0};

char cpre580f98[] = "netdump";//not sure yet

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packet_type; //ICMP(1), UDP(17), TCP(6) etc.

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int); //Berkey packet Filter

extern char *copy_argv(char **);

// Forwards //Edited THis, added the session struct
void program_ending(Session session, int);

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
			  currSession.broadcast_packets_total);
	    (void)fprintf(stderr, "Number of IP Packets = %d\n",
			  currSession_ip_packets_total);
	    (void)fprintf(stderr, "Number of ARP Packets = %d\n",
			  currSession_arp_packets_total);
	    (void)fprintf(stderr, "Number of ICMP Packets = %d\n",
			  currSession_icmp_packets_total);    	    
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
 * This is used as the callback function for pcap_loop. 
 * it is called every time a packet is received. 
 * caplen is the length of the ethernet packet
 * character array p, which is the packet p[0] DEST hardware address
 */
void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
  u_int length = h->len;
  u_int caplen = h->caplen; //the length of the ethernet packet


  Packet currPacket;
  currPacket.raw_data = (u_char*)malloc(caplen * sizeof(p));
  currPacket.length = length;
  currPacket.caplen = caplen;
  int iter = 0;
  for(iter = 0; iter < caplen; iter++){
    currPacket.raw_data[iter] = p[iter];
  }
  set_header(&currPacket);
  
  printf("\n\t +++++++++++[START OF DECODE]+++++++++++\n");

  
  print_packet_header(p);
  //Printing the packet
  printf("\n\t -------[END OF DECODE]-------\n");
  printf("\n\t +++++++++++[RAW DATA]+++++++++++\n");
  default_print(p, caplen);
  putchar('\n');  
  printf("\n\t ------------[END OF DATA]------------\n");
  free(currPacket.raw_data);
}

/*
void set_header(Packet *packet){
  int i = 0;
  int length_of_address = 6;
  for(i = 0; i< length_of_address; i++){
    packet->dest_addr[i] = packet->raw_data[i];
  }
  for(i=0; i<length_of_address; i++){
    packet->src_addr[i] = packet->raw_data[i];
  }

  packet->type_length = packet[i++]*256 + packet[i++];

  
}
*/

/*
 * Print the ethernet header of the packet
 *

void print_packet_header(u_char *packet){
  num_broadcast_packets++;
  char *PACKET_PRINT_FORMAT_IPV6 = "%s = %02x:%02x:%02x:%02x:%02x:%02x\n";
  int i = 0;
  char *dst_addr = "DEST Address";
  char *src_addr = "SRC Address ";
  printf(PACKET_PRINT_FORMAT_IPV6, dst_addr, packet[i++], packet[i++],\
	 packet[i++], packet[i++], packet[i++], packet[i++]);
  printf(PACKET_PRINT_FORMAT_IPV6, src_addr, packet[6], packet[7],\
	 packet[i++], packet[i++], packet[i++], packet[i++]);
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
   
   // if(type_or_length == IP){
     // printf("Payload = IP\n");
     // num_ip_packets++;
   // }
    
    if(type_or_length == ARP){
      printf("Payload = ARP\n");
      num_arp_packets++;
      //first try putting the whole thing ing
      decode_ARP_packet(packet);
      //Call function that prints out ARP
    }
    
    // else if(type_or_length == IPv6 ){
    // printf("Payload = IPv6\n");
      //increment this?
    // }else{
    // printf("Payload is not yet mapped\n");
      //still don't know what 0x9000 is
      //0x7bda,
      //0x2715, 
      //0x1baa,
      //0x1856,
    }
   
  }  
}
*/
/* 
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
    printf("ARP Reply\n");
  }else {
    printf("Error : Unknown Arp Operation");
  }
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
*/
