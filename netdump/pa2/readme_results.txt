Will Sartin
CPRE - 530
Programming Assignment 2
6-27-2019

Chapter 5-Decode Header
         +++++++++++[START OF PACKET]+++++++++++                                                         
DEST Address = 00:50:56:86:06:d3                                                                         
SRC Address  = 00:00:0c:31:01:aa                                                                         
Type = 0x0800, Payload = IP                                                                              
                                                                                                         
         0050 5686 06d3 0000 0c31 01aa 0800 4500                                                         
         006a 56e1 4000 3c06 cc42 c764 1064 4027                                                         
         037b 0c38 cff4 9972 4fe7 5f17 b2b6 8018                                                         
         0410 9856 0000 0101 080a 92f3 2417 ada7                                                         
         a956 1703 0300 313d 6f81 806e d78d da89                                                         
         5a67 0786 a2f7 2817 40ca 44eb 2734 a34c                                                         
         c3d4 ec17 a30f 5916 ce01 1a59 5c69 9484                                                         
         a774 b530 19ae 7327                                                                             
                                                                                                         
         ------------[END OF PACKET]------------                                                         
                                                                                                         
         +++++++++++[START OF PACKET]+++++++++++                                                         
DEST Address = 00:00:0c:31:01:aa                                                                         
SRC Address  = 00:50:56:86:06:d3                                                                         
Type = 0x0800, Payload = IP                                                                              
                                                                                                         
         0000 0c31 01aa 0050 5686 06d3 0800 4500                                                         
         0034 d1d9 4000 4006 4d80 4027 037b c764                                                         
         1064 cff4 0c38 5f17 b2b6 9972 501d 8010                                                         
         014c 5ca2 0000 0101 080a ada7 c127 92f3                                                         
         2417                                                                                            
                                                                                                         
         ------------[END OF PACKET]------------                                                         
294 packets received by filer                                                                            
0 packets dropped by kernel                                                                              
Number of Broadcast Packets = 268                                                                        
Number of IP Packets = 264                                                                               
Number of ARP Packets = 2                                                                                
   

+------------------------------------------------------------------------------+

		Chapter 6-ARP, IP, ICMP



Part A: ARP
	 -----------[START OF DECODE]------------
DEST Address = da:7b:96:76:04:00
SRC Address  = 15:27:19:e3:16:00
Type = 0x0806, Payload = ARP
Arp PacketHardware type: 1
Protocol Type: 2048
Hardware Length: 6
Protocol Length: 4
Operation: 1
ARP Request
Sender Hardware Address: 00:16:e3:19:27:15
Sender Protocol Address: 247.138.53.45
Target Hardware Address: 00:00:00:00:00:00
Target Protocol Address: 247.138.53.49

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0004 7696 7bda 0016 e319 2715 0806 0001
	 0800 0604 0001 0016 e319 2715 f78a 352d
	 0000 0000 0000 f78a 3531 0000 0000 0000
	 0000 0000 0000 0000 0000 0000

	 ------------[END OF RAW DATA]------------

	 -----------[START OF DECODE]------------
DEST Address = 15:27:19:e3:16:00
SRC Address  = da:7b:96:76:04:00
Type = 0x0806, Payload = ARP
Arp PacketHardware type: 1
Protocol Type: 2048
Hardware Length: 6
Protocol Length: 4
Operation: 2
ARP Reply
Sender Hardware Address: 00:04:76:96:7b:da
Sender Protocol Address: 247.138.53.49
Target Hardware Address: 00:16:e3:19:27:15
Target Protocol Address: 247.138.53.45

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0016 e319 2715 0004 7696 7bda 0806 0001
	 0800 0604 0002 0004 7696 7bda f78a 3531
	 0016 e319 2715 f78a 352d 0000 0000 0000
	 0000 0000 0000 0000 0000 0000

	 ------------[END OF RAW DATA]------------

Part B: IP

	 -----------[START OF DECODE]------------
DEST Address = da:7b:96:76:04:00
SRC Address  = 15:27:19:e3:16:00
Type = 0x0800, Payload = IP
IP Packet Header::
Version: 4
Header length:20
Service Type: 0 
Length of the Payload: 126
Identifier: 0
Flag: 0 1 0
Offset = 0
TTL: 64
Protocol: 17
Checksum: 32333
Src IP Address 231.156.118.117
Dst IP Address 231.156.118.115
Protocol is UDP

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0004 7696 7bda 0016 e319 2715 0800 4500
	 007e 0000 4000 4011 7e4d e79c 7675 e79c
	 7673 0035 0850 006a 84ea 313d 8180 0001
	 0001 0000 0000 0332 3431 0332 3533 0331
	 3234 0331 3635 0769 6e2d 6164 6472 0461
	 7270 6100 000c 0001 c00c 000c 0001 0000
	 3840 0028 0b65 6e67 6d61 6e6c 6162 3130
	 0970 6174 686f 6c6f 6779 0c6e 6f72 7468
	 7765 7374 6572 6e03 6564 7500

	 ------------[END OF RAW DATA]------------

	 -----------[START OF DECODE]------------
DEST Address = da:7b:96:76:04:00
SRC Address  = 15:27:19:e3:16:00
Type = 0x0800, Payload = IP
IP Packet Header::
Version: 4
Header length:20
Service Type: 0 
Length of the Payload: 56
Identifier: 43440
Flag: 0 1 0
Offset = 0
TTL: 48
Protocol: 1
Checksum: 53295
Src IP Address 191.239.178.229
Dst IP Address 231.156.118.115
Protocol: ICMP::
Type: 3, Code: 3
Checksum: 5032
	Dest unreachable

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0004 7696 7bda 0016 e319 2715 0800 4500
	 0038 a9b0 4000 3001 d02f bfef b2e5 e79c
	 7673 0303 13a8 0000 0000 4500 002e 0000
	 4000 3011 8f17 c0a8 0102 5680 a37d 8c96
	 6532 001a f771

	 ------------[END OF RAW DATA]------------

	 -----------[START OF DECODE]------------
DEST Address = aa:01:31:0c:00:00
SRC Address  = 20:98:86:56:50:00
Type = 0x0800, Payload = IP
IP Packet Header::
Version: 4
Header length:20
Service Type: 0 
Length of the Payload: 84
Identifier: 51646
Flag: 0 1 0
Offset = 0
TTL: 64
Protocol: 1
Checksum: 21837
Src IP Address 64.39.3.174
Dst IP Address 199.100.16.100
Protocol: ICMP::
Type: 8, Code: 0
Checksum: 58181
	ICMP ECHO Request

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0000 0c31 01aa 0050 5686 9820 0800 4500
	 0054 c9be 4000 4001 554d 4027 03ae c764
	 1064 0800 e345 0b05 0001 1777 115d 0000
	 0000 220d 0000 0000 0000 1011 1213 1415
	 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425
	 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435
	 3637

	 ------------[END OF RAW DATA]------------

	 -----------[START OF DECODE]------------
DEST Address = 20:98:86:56:50:00
SRC Address  = aa:01:31:0c:00:00
Type = 0x0800, Payload = IP
IP Packet Header::
Version: 4
Header length:20
Service Type: 0 
Length of the Payload: 84
Identifier: 12273
Flag: 0 1 0
Offset = 0
TTL: 60
Protocol: 1
Checksum: 62234
Src IP Address 199.100.16.100
Dst IP Address 64.39.3.174
Protocol: ICMP::
Type: 0, Code: 0
Checksum: 60229
	ICMP ECHO Reply

	 -------[END OF DECODE]-------

	 -----------[START OF RAW DATA]-----------

	 0050 5686 9820 0000 0c31 01aa 0800 4500
	 0054 2ff1 4000 3c01 f31a c764 1064 4027
	 03ae 0000 eb45 0b05 0001 1777 115d 0000
	 0000 220d 0000 0000 0000 1011 1213 1415
	 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425
	 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435
	 3637

610 packets received by filter
0 packets fropped by kernel
Number of Broascast Packets = 610
Number of IP Packets = 592
Number of ARP Packets = 15
Number of ICMP Packets = 45



Chapter 7-TCP

         -----------[START OF DECODE]------------                                                        
DEST Address = aa:01:31:0c:00:00                                                                         
SRC Address  = 21:19:86:56:50:00                                                                         
Type = 0x0800, Payload = IP                                                                              
IP Packet Header::                                                                                       
Version: 4                                                                                               
Header length:20                                                                                         
Service Type: 0                                                                                          
Length of the Payload: 91                                                                                
Identifier: 24417                                                                                        
Flag: 0 1 0                                                                                              
Offset = 0                                                                                               
TTL: 64                                                                                                  
Protocol: 6                                                                                              
Checksum: 49060                                                                                          
Src IP Address 64.39.3.168                                                                               
Dst IP Address 199.100.16.100                                                                            
Protocol is TCP                                                                                          
Source Port Num: 49392                                                                                   
Destination Porn Num: 3128                                                                               
Sequence Num: 3679109285                                                                                 
Acknowledge Num: 3491561692                                                                              
Header Length: 0 
Reserved: 0                                                                                              
Flags: 24                                                                                                
Flag              Function               Value                                                           
URG      Packet Contains Urgent Data       0                                                             
ACK           Ack Num Is Valid             1                                                             
PSH     Data Should be pushed to Appl      1                                                             
RST              Reset Packet              0                                                             
SYN           Synchronize Packet           0                                                             
FIN            Finish Packet               0                                                             
Window size: 1024                                                                                        
Checksum: 38947                                                                                          
Urgent Pointer: 0                                                                                        
Options---                                                                                               
118a1414beacbc47a0bd1733022507a8b                                                                        
                                                                                                         
         -------[END OF DECODE]-------                                                                   
                                                                                                         
         -----------[START OF RAW DATA]-----------                                                       
                                                                                                         
         0000 0c31 01aa 0050 5686 1921 0800 4500                                                         
         005b 5f61 4000 4006 bfa4 4027 03a8 c764                                                         
         1064 c0f0 0c38 db4a c0a5 d01d 00dc 8018                                                         
         0102 9823 0000 0101 080a 1414 beac bc47                                                         
         a0bd 1703 0300 2250 7a8b 2329 967d 0680                                                         
         0ab5 e8ef f173 a0c7 63a0 a1fa 0a17 0735                                                         
         40d4 8e78 a4ae 922f 3e                                                                          
                                                                                                         
         ------------[END OF RAW DATA]------------                                                       
                               

141 packets received by filter                                                                           
0 packets dropped by the kernel                                                                          
Number of Broadcast Packets = 132                                                                        
Number of IP Packets = 120                                                                               
Number of ARP Packets = 2                                                                                
Number of ICMP Packets = 0                                                                               
Number of TCP Packets = 125                                                                              
                             
