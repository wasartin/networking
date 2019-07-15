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

char cpre580f98[] = "netdump";//not sure yet

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packet_type; //ICMP(1), UDP(17), TCP(6) etc.

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int); //Berkey packet Filter

extern char *copy_argv(char **);

// Forwards //Edited THis, added the session struct
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;
Session currSession;
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
  currSession.broadcast_packets_total = 0;
  currSession.ip_packets_total = 0;
  currSession.arp_packets_total = 0;
  currSession.icmp_packets_total = 0;
  currSession.tcp_packets_total = 0;
  currSession.udp_packets_total = 0;
  if ((cp = strrchr(argv[0], '/')) != NULL){
    program_name = cp + 1;
  }else{
    program_name = argv[0];
  }
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
    }else {
      (void)fprintf(stderr, "%d packets received by filter\n",
		    stat.ps_recv);
      (void)fprintf(stderr, "%d packets dropped by kernel\n",
		    stat.ps_drop);
      (void)fprintf(stderr, "Number of Broadcast Packets = %d\n",
		    currSession.broadcast_packets_total);
      (void)fprintf(stderr, "Number of IP Packets = %d\n",
		    currSession.ip_packets_total);
      (void)fprintf(stderr, "Number of ARP Packets = %d\n",
		    currSession.arp_packets_total);
      (void)fprintf(stderr, "Number of ICMP Packets = %d\n",
		    currSession.icmp_packets_total);
      (void)fprintf(stderr, "Number of TCP Packets = %d\n",
		    currSession.tcp_packets_total);
      (void)fprintf(stderr, "Number of UDP Packets = %d\n",
		    currSession.udp_packets_total);    	    
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

  printf("\n\t -----------[START OF DECODE]------------\n");  
  print_packet_header(p);
  printf("\n\t -------[END OF DECODE]-------\n");
  printf("\n\t -----------[START OF RAW DATA]-----------\n");
  default_print(p, caplen);
  putchar('\n');  
  printf("\n\t ------------[END OF RAW DATA]------------\n");
  //  free(currPacket.raw_data);
}


