#pragma once

enum class NextHeader : unsigned char {
	NH_HOPOPT = 0, // 0x00 HOPOPT IPv6 Hop-by-Hop Option RFC 8200
	NH_ICMP = 1, // 0x01 ICMP Internet Control Message Protocol RFC 792
	NH_IGMP = 2, // 0x02 IGMP Internet Group Management Protocol RFC 1112
	NH_GGP = 3, // 0x03 GGP Gateway-to-Gateway Protocol RFC 823
	NH_IPinIP = 4, // 0x04 IP-in-IP IP in IP (encapsulation) RFC 2003
	NH_ST = 5, // 0x05 ST Internet Stream Protocol RFC 1190, RFC 1819
	NH_TCP = 6, // 0x06 TCP Transmission Control Protocol RFC 793
	NH_CBT = 7, // 0x07 CBT Core-based trees RFC 2189
	NH_EGP = 8, // 0x08 EGP Exterior Gateway Protocol RFC 888
	NH_IGP = 9, // 0x09 IGP Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP)) 
	NH_BBNRCCMON = 10, // 0x0A BBN-RCC-MON BBN RCC Monitoring 
	NH_NVPII = 11, // 0x0B NVP-II Network Voice Protocol RFC 741
	NH_PUP = 12, // 0x0C PUP Xerox PUP 
	NH_ARGUS = 13, // 0x0D ARGUS ARGUS 
	NH_EMCON = 14, // 0x0E EMCON EMCON 
	NH_XNET = 15, // 0x0F XNET Cross Net Debugger IEN 158[2]
	NH_CHAOS = 16, // 0x10 CHAOS Chaos 
	NH_UDP = 17, // 0x11 UDP User Datagram Protocol RFC 768
	NH_MUX = 18, // 0x12 MUX Multiplexing IEN 90[3]
	NH_DCNMEAS = 19, // 0x13 DCN-MEAS DCN Measurement Subsystems 
	NH_HMP = 20, // 0x14 HMP Host Monitoring Protocol RFC 869
	NH_PRM = 21, // 0x15 PRM Packet Radio Measurement 
	NH_XNSIDP = 22, // 0x16 XNS-IDP XEROX NS IDP 
	NH_TRUNK1 = 23, // 0x17 TRUNK-1 Trunk-1 
	NH_TRUNK2 = 24, // 0x18 TRUNK-2 Trunk-2 
	NH_LEAF1 = 25, // 0x19 LEAF-1 Leaf-1 
	NH_LEAF2 = 26, // 0x1A LEAF-2 Leaf-2 
	NH_RDP = 27, // 0x1B RDP Reliable Data Protocol RFC 908
	NH_IRTP = 28, // 0x1C IRTP Internet Reliable Transaction Protocol RFC 938
	NH_ISOTP4 = 29, // 0x1D ISO-TP4 ISO Transport Protocol Class 4 RFC 905
	NH_NETBLT = 30, // 0x1E NETBLT Bulk Data Transfer Protocol RFC 998
	NH_MFENSP = 31, // 0x1F MFE-NSP MFE Network Services Protocol 
	NH_MERITINP = 32, // 0x20 MERIT-INP MERIT Internodal Protocol 
	NH_DCCP = 33, // 0x21 DCCP Datagram Congestion Control Protocol RFC 4340
	NH_3PC = 34, // 0x22 3PC Third Party Connect Protocol 
	NH_IDPR = 35, // 0x23 IDPR Inter-Domain Policy Routing Protocol RFC 1479
	NH_XTP = 36, // 0x24 XTP Xpress Transport Protocol 
	NH_DDP = 37, // 0x25 DDP Datagram Delivery Protocol 
	NH_IDPRCMTP = 38, // 0x26 IDPR-CMTP IDPR Control Message Transport Protocol 
	NH_TPPP = 39, // 0x27 TP++ TP++ Transport Protocol 
	NH_IL = 40, // 0x28 IL IL Transport Protocol 
	NH_IPv6 = 41, // 0x29 IPv6 IPv6 Encapsulation RFC 2473
	NH_SDRP = 42, // 0x2A SDRP Source Demand Routing Protocol RFC 1940
	NH_IPv6Route = 43, // 0x2B IPv6-Route Routing Header for IPv6 RFC 8200
	NH_IPv6Frag = 44, // 0x2C IPv6-Frag Fragment Header for IPv6 RFC 8200
	NH_IDRP = 45, // 0x2D IDRP Inter-Domain Routing Protocol 
	NH_RSVP = 46, // 0x2E RSVP Resource Reservation Protocol RFC 2205
	NH_GREs = 47, // 0x2F GREs Generic Routing Encapsulation RFC 2784, RFC 2890
	NH_DSR = 48, // 0x30 DSR Dynamic Source Routing Protocol RFC 4728
	NH_BNA = 49, // 0x31 BNA Burroughs Network Architecture 
	NH_ESP = 50, // 0x32 ESP Encapsulating Security Payload RFC 4303
	NH_AH = 51, // 0x33 AH Authentication Header RFC 4302
	NH_INLSP = 52, // 0x34 I-NLSP Integrated Net Layer Security Protocol TUBA
	NH_SwIPe = 53, // 0x35 SwIPe SwIPe RFC 5237
	NH_NARP = 54, // 0x36 NARP NBMA Address Resolution Protocol RFC 1735
	NH_MOBILE = 55, // 0x37 MOBILE IP Mobility (Min Encap) RFC 2004
	NH_TLSP = 56, // 0x38 TLSP Transport Layer Security Protocol (using Kryptonet key management) 
	NH_SKIP = 57, // 0x39 SKIP Simple Key-Management for Internet Protocol RFC 2356
	NH_IPv6ICMP = 58, // 0x3A IPv6-ICMP ICMP for IPv6 RFC 4443, RFC 4884
	NH_IPv6NoNxt = 59, // 0x3B IPv6-NoNxt No Next Header for IPv6 RFC 8200
	NH_IPv6Opts = 60, // 0x3C IPv6-Opts Destination Options for IPv6 RFC 8200
	NH_HostInternalProtocol = 61, // 0x3D  Any host internal protocol 
	NH_CFTP = 62, // 0x3E CFTP CFTP 
	NH_LocalNetwork = 63, // 0x3F  Any local network 
	NH_SATEXPAK = 64, // 0x40 SAT-EXPAK SATNET and Backroom EXPAK 
	NH_KRYPTOLAN = 65, // 0x41 KRYPTOLAN Kryptolan 
	NH_RVD = 66, // 0x42 RVD MIT Remote Virtual Disk Protocol 
	NH_IPPC = 67, // 0x43 IPPC Internet Pluribus Packet Core 
	NH_DistributedFileSystem = 68, // 0x44  Any distributed file system 
	NH_SATMON = 69, // 0x45 SAT-MON SATNET Monitoring 
	NH_VISA = 70, // 0x46 VISA VISA Protocol 
	NH_IPCU = 71, // 0x47 IPCU Internet Packet Core Utility 
	NH_CPNX = 72, // 0x48 CPNX Computer Protocol Network Executive 
	NH_CPHB = 73, // 0x49 CPHB Computer Protocol Heart Beat 
	NH_WSN = 74, // 0x4A WSN Wang Span Network 
	NH_PVP = 75, // 0x4B PVP Packet Video Protocol 
	NH_BRSATMON = 76, // 0x4C BR-SAT-MON Backroom SATNET Monitoring 
	NH_SUNND = 77, // 0x4D SUN-ND SUN ND PROTOCOL-Temporary 
	NH_WBMON = 78, // 0x4E WB-MON WIDEBAND Monitoring 
	NH_WBEXPAK = 79, // 0x4F WB-EXPAK WIDEBAND EXPAK 
	NH_ISOIP = 80, // 0x50 ISO-IP International Organization for Standardization Internet Protocol 
	NH_VMTP = 81, // 0x51 VMTP Versatile Message Transaction Protocol RFC 1045
	NH_SECUREVMTP = 82, // 0x52 SECURE-VMTP Secure Versatile Message Transaction Protocol RFC 1045
	NH_VINES = 83, // 0x53 VINES VINES 
	NH_TTP = 84, // 0x54 TTP TTP 
	NH_IPTM = 84, // 0x54 IPTM Internet Protocol Traffic Manager 
	NH_NSFNETIGP = 85, // 0x55 NSFNET-IGP NSFNET-IGP 
	NH_DGP = 86, // 0x56 DGP Dissimilar Gateway Protocol 
	NH_TCF = 87, // 0x57 TCF TCF 
	NH_EIGRP = 88, // 0x58 EIGRP EIGRP Informational RFC 7868
	NH_OSPF = 89, // 0x59 OSPF Open Shortest Path First RFC 2328
	NH_SpriteRPC = 90, // 0x5A Sprite-RPC Sprite RPC Protocol 
	NH_LARP = 91, // 0x5B LARP Locus Address Resolution Protocol 
	NH_MTP = 92, // 0x5C MTP Multicast Transport Protocol 
	NH_AX25 = 93, // 0x5D AX.25 AX.25 
	NH_OS = 94, // 0x5E OS KA9Q NOS compatible IP over IP tunneling 
	NH_MICP = 95, // 0x5F MICP Mobile Internetworking Control Protocol 
	NH_SCCSP = 96, // 0x60 SCC-SP Semaphore Communications Sec. Pro 
	NH_ETHERIP = 97, // 0x61 ETHERIP Ethernet-within-IP Encapsulation RFC 3378
	NH_ENCAP = 98, // 0x62 ENCAP Encapsulation Header RFC 1241
	NH_PrivateEncryptionScheme = 99, // 0x63  Any private encryption scheme 
	NH_GMTP = 100, // 0x64 GMTP GMTP 
	NH_IFMP = 101, // 0x65 IFMP Ipsilon Flow Management Protocol 
	NH_PNNI = 102, // 0x66 PNNI PNNI over IP 
	NH_PIM = 103, // 0x67 PIM Protocol Independent Multicast 
	NH_ARIS = 104, // 0x68 ARIS IBM's ARIS (Aggregate Route IP Switching) Protocol 
	NH_SCPS = 105, // 0x69 SCPS SCPS (Space Communications Protocol Standards) SCPS-TP[4]
	NH_QNX = 106, // 0x6A QNX QNX 
	NH_AN = 107, // 0x6B A/N Active Networks 
	NH_IPComp = 108, // 0x6C IPComp IP Payload Compression Protocol RFC 3173
	NH_SNP = 109, // 0x6D SNP Sitara Networks Protocol 
	NH_CompaqPeer = 110, // 0x6E Compaq-Peer Compaq Peer Protocol 
	NH_IPXinIP = 111, // 0x6F IPX-in-IP IPX in IP 
	NH_VRRP = 112, // 0x70 VRRP Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned) VRRP:RFC 3768
	NH_PGM = 113, // 0x71 PGM PGM Reliable Transport Protocol RFC 3208
	NH_ZeroHopProtocol = 114, // 0x72  Any 0-hop protocol 
	NH_L2TP = 115, // 0x73 L2TP Layer Two Tunneling Protocol Version 3 RFC 3931
	NH_DDX = 116, // 0x74 DDX D-II Data Exchange (DDX) 
	NH_IATP = 117, // 0x75 IATP Interactive Agent Transfer Protocol 
	NH_STP = 118, // 0x76 STP Schedule Transfer Protocol 
	NH_SRP = 119, // 0x77 SRP SpectraLink Radio Protocol 
	NH_UTI = 120, // 0x78 UTI Universal Transport Interface Protocol 
	NH_SMP = 121, // 0x79 SMP Simple Message Protocol 
	NH_SM = 122, // 0x7A SM Simple Multicast Protocol draft-perlman-simple-multicast-03
	NH_PTP = 123, // 0x7B PTP Performance Transparency Protocol 
	NH_ISISoIPv4 = 124, // 0x7C IS-IS over IPv4 Intermediate System to Intermediate System (IS-IS) Protocol over IPv4 RFC 1142 and RFC 1195
	NH_FIRE = 125, // 0x7D FIRE Flexible Intra-AS Routing Environment 
	NH_CRTP = 126, // 0x7E CRTP Combat Radio Transport Protocol 
	NH_CRUDP = 127, // 0x7F CRUDP Combat Radio User Datagram 
	NH_SSCOPMCE = 128, // 0x80 SSCOPMCE Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment ITU-T Q.2111 (1999)
	NH_IPLT = 129, // 0x81 IPLT  
	NH_SPS = 130, // 0x82 SPS Secure Packet Shield 
	NH_PIPE = 131, // 0x83 PIPE Private IP Encapsulation within IP Expired I-D draft-petri-mobileip-pipe-00.txt
	NH_SCTP = 132, // 0x84 SCTP Stream Control Transmission Protocol RFC 4960
	NH_FC = 133, // 0x85 FC Fibre Channel 
	NH_RSVPE2EIGNORE = 134, // 0x86 RSVP-E2E-IGNORE Reservation Protocol (RSVP) End-to-End Ignore RFC 3175
	NH_MobilityHeader = 135, // 0x87 Mobility Header Mobility Extension Header for IPv6 RFC 6275
	NH_UDPLite = 136, // 0x88 UDPLite Lightweight User Datagram Protocol RFC 3828
	NH_MPLSinIP = 137, // 0x89 MPLS-in-IP Multiprotocol Label Switching Encapsulated in IP RFC 4023, RFC 5332
	NH_manet = 138, // 0x8A manet MANET Protocols RFC 5498
	NH_HIP = 139, // 0x8B HIP Host Identity Protocol RFC 5201
	NH_Shim6 = 140, // 0x8C Shim6 Site Multihoming by IPv6 Intermediation RFC 5533
	NH_WESP = 141, // 0x8D WESP Wrapped Encapsulating Security Payload RFC 5840
	NH_ROHC = 142, // 0x8E ROHC Robust Header Compression RFC 5856
	NH_Ethernet = 143, // 0x8F Ethernet IPv6 Segment Routing (TEMPORARY - registered 2020-01-31, expires 2021-01-31) 
	NH_Unassigned144 = 144, // 0x90 Unassigned  
	NH_Unassigned145 = 145, // 0x91 Unassigned  
	NH_Unassigned146 = 146, // 0x92 Unassigned  
	NH_Unassigned147 = 147, // 0x93 Unassigned  
	NH_Unassigned148 = 148, // 0x94 Unassigned  
	NH_Unassigned149 = 149, // 0x95 Unassigned  
	NH_Unassigned150 = 150, // 0x96 Unassigned  
	NH_Unassigned151 = 151, // 0x97 Unassigned  
	NH_Unassigned152 = 152, // 0x98 Unassigned  
	NH_Unassigned153 = 153, // 0x99 Unassigned  
	NH_Unassigned154 = 154, // 0x9A Unassigned  
	NH_Unassigned155 = 155, // 0x9B Unassigned  
	NH_Unassigned156 = 156, // 0x9C Unassigned  
	NH_Unassigned157 = 157, // 0x9D Unassigned  
	NH_Unassigned158 = 158, // 0x9E Unassigned  
	NH_Unassigned159 = 159, // 0x9F Unassigned  
	NH_Unassigned160 = 160, // 0xA0 Unassigned  
	NH_Unassigned161 = 161, // 0xA1 Unassigned  
	NH_Unassigned162 = 162, // 0xA2 Unassigned  
	NH_Unassigned163 = 163, // 0xA3 Unassigned  
	NH_Unassigned164 = 164, // 0xA4 Unassigned  
	NH_Unassigned165 = 165, // 0xA5 Unassigned  
	NH_Unassigned166 = 166, // 0xA6 Unassigned  
	NH_Unassigned167 = 167, // 0xA7 Unassigned  
	NH_Unassigned168 = 168, // 0xA8 Unassigned  
	NH_Unassigned169 = 169, // 0xA9 Unassigned  
	NH_Unassigned170 = 170, // 0xAA Unassigned  
	NH_Unassigned171 = 171, // 0xAB Unassigned  
	NH_Unassigned172 = 172, // 0xAC Unassigned  
	NH_Unassigned173 = 173, // 0xAD Unassigned  
	NH_Unassigned174 = 174, // 0xAE Unassigned  
	NH_Unassigned175 = 175, // 0xAF Unassigned  
	NH_Unassigned176 = 176, // 0xB0 Unassigned  
	NH_Unassigned177 = 177, // 0xB1 Unassigned  
	NH_Unassigned178 = 178, // 0xB2 Unassigned  
	NH_Unassigned179 = 179, // 0xB3 Unassigned  
	NH_Unassigned180 = 180, // 0xB4 Unassigned  
	NH_Unassigned181 = 181, // 0xB5 Unassigned  
	NH_Unassigned182 = 182, // 0xB6 Unassigned  
	NH_Unassigned183 = 183, // 0xB7 Unassigned  
	NH_Unassigned184 = 184, // 0xB8 Unassigned  
	NH_Unassigned185 = 185, // 0xB9 Unassigned  
	NH_Unassigned186 = 186, // 0xBA Unassigned  
	NH_Unassigned187 = 187, // 0xBB Unassigned  
	NH_Unassigned188 = 188, // 0xBC Unassigned  
	NH_Unassigned189 = 189, // 0xBD Unassigned  
	NH_Unassigned190 = 190, // 0xBE Unassigned  
	NH_Unassigned191 = 191, // 0xBF Unassigned  
	NH_Unassigned192 = 192, // 0xC0 Unassigned  
	NH_Unassigned193 = 193, // 0xC1 Unassigned  
	NH_Unassigned194 = 194, // 0xC2 Unassigned  
	NH_Unassigned195 = 195, // 0xC3 Unassigned  
	NH_Unassigned196 = 196, // 0xC4 Unassigned  
	NH_Unassigned197 = 197, // 0xC5 Unassigned  
	NH_Unassigned198 = 198, // 0xC6 Unassigned  
	NH_Unassigned199 = 199, // 0xC7 Unassigned  
	NH_Unassigned200 = 200, // 0xC8 Unassigned  
	NH_Unassigned201 = 201, // 0xC9 Unassigned  
	NH_Unassigned202 = 202, // 0xCA Unassigned  
	NH_Unassigned203 = 203, // 0xCB Unassigned  
	NH_Unassigned204 = 204, // 0xCC Unassigned  
	NH_Unassigned205 = 205, // 0xCD Unassigned  
	NH_Unassigned206 = 206, // 0xCE Unassigned  
	NH_Unassigned207 = 207, // 0xCF Unassigned  
	NH_Unassigned208 = 208, // 0xD0 Unassigned  
	NH_Unassigned209 = 209, // 0xD1 Unassigned  
	NH_Unassigned210 = 210, // 0xD2 Unassigned  
	NH_Unassigned211 = 211, // 0xD3 Unassigned  
	NH_Unassigned212 = 212, // 0xD4 Unassigned  
	NH_Unassigned213 = 213, // 0xD5 Unassigned  
	NH_Unassigned214 = 214, // 0xD6 Unassigned  
	NH_Unassigned215 = 215, // 0xD7 Unassigned  
	NH_Unassigned216 = 216, // 0xD8 Unassigned  
	NH_Unassigned217 = 217, // 0xD9 Unassigned  
	NH_Unassigned218 = 218, // 0xDA Unassigned  
	NH_Unassigned219 = 219, // 0xDB Unassigned  
	NH_Unassigned220 = 220, // 0xDC Unassigned  
	NH_Unassigned221 = 221, // 0xDD Unassigned  
	NH_Unassigned222 = 222, // 0xDE Unassigned  
	NH_Unassigned223 = 223, // 0xDF Unassigned  
	NH_Unassigned224 = 224, // 0xE0 Unassigned  
	NH_Unassigned225 = 225, // 0xE1 Unassigned  
	NH_Unassigned226 = 226, // 0xE2 Unassigned  
	NH_Unassigned227 = 227, // 0xE3 Unassigned  
	NH_Unassigned228 = 228, // 0xE4 Unassigned  
	NH_Unassigned229 = 229, // 0xE5 Unassigned  
	NH_Unassigned230 = 230, // 0xE6 Unassigned  
	NH_Unassigned231 = 231, // 0xE7 Unassigned  
	NH_Unassigned232 = 232, // 0xE8 Unassigned  
	NH_Unassigned233 = 233, // 0xE9 Unassigned  
	NH_Unassigned234 = 234, // 0xEA Unassigned  
	NH_Unassigned235 = 235, // 0xEB Unassigned  
	NH_Unassigned236 = 236, // 0xEC Unassigned  
	NH_Unassigned237 = 237, // 0xED Unassigned  
	NH_Unassigned238 = 238, // 0xEE Unassigned  
	NH_Unassigned239 = 239, // 0xEF Unassigned  
	NH_Unassigned240 = 240, // 0xF0 Unassigned  
	NH_Unassigned241 = 241, // 0xF1 Unassigned  
	NH_Unassigned242 = 242, // 0xF2 Unassigned  
	NH_Unassigned243 = 243, // 0xF3 Unassigned  
	NH_Unassigned244 = 244, // 0xF4 Unassigned  
	NH_Unassigned245 = 245, // 0xF5 Unassigned  
	NH_Unassigned246 = 246, // 0xF6 Unassigned  
	NH_Unassigned247 = 247, // 0xF7 Unassigned  
	NH_Unassigned248 = 248, // 0xF8 Unassigned  
	NH_Unassigned249 = 249, // 0xF9 Unassigned  
	NH_Unassigned250 = 250, // 0xFA Unassigned  
	NH_Unassigned251 = 251, // 0xFB Unassigned  
	NH_Unassigned252 = 252, // 0xFC Unassigned  
	NH_Experimental253 = 253, // 0xFD Use for experimentation and testing  RFC 3692
	NH_Experimental254 = 254, // 0xFE Use for experimentation and testing  RFC 3692
	NH_Reserved = 255 // 0xFF Reserved  
};