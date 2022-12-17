/* come from tcpdump,changed to little edian
 * Copyright (c) 1993, 1994, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Maximum length of the length field in an Ethernet header; any value
 * greater than this is not a length value, so it's either an Ethernet
 * type or an invalid value.
 */
#define MAX_ETHERNET_LENGTH_VAL 1500

/*
 * Ethernet types.
 *
 * We wrap the declarations with #ifdef, so that if a file includes
 * <netinet/if_ether.h>, which may declare some of these, we don't
 * get a bunch of complaints from the C compiler about redefinitions
 * of these values.
 *
 * We declare all of them here so that no file has to include
 * <netinet/if_ether.h> if all it needs are ETHERTYPE_ values.
 */

#ifndef ETHERTYPE_LEN
#define ETHERTYPE_LEN 2
#endif

#ifndef ETHERTYPE_GRE_ISO
#define ETHERTYPE_GRE_ISO 0xFE00 /* not really an ethertype only used in GRE */
#endif
#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP 0x0002 /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0008 /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0608 /* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP 0x3580 /* reverse Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_NS
#define ETHERTYPE_NS 0x0006
#endif
#ifndef ETHERTYPE_SPRITE
#define ETHERTYPE_SPRITE 0x0005
#endif
#ifndef ETHERTYPE_TRAIL
#define ETHERTYPE_TRAIL 0x0010
#endif
#ifndef ETHERTYPE_MOPDL
#define ETHERTYPE_MOPDL 0x0160
#endif
#ifndef ETHERTYPE_MOPRC
#define ETHERTYPE_MOPRC 0x0260
#endif
#ifndef ETHERTYPE_DN
#define ETHERTYPE_DN 0x0360
#endif
#ifndef ETHERTYPE_LAT
#define ETHERTYPE_LAT 0x0460
#endif
#ifndef ETHERTYPE_SCA
#define ETHERTYPE_SCA 0x0760
#endif
#ifndef ETHERTYPE_TEB
#define ETHERTYPE_TEB 0x5865
#endif
#ifndef ETHERTYPE_LANBRIDGE
#define ETHERTYPE_LANBRIDGE 0x3880
#endif
#ifndef ETHERTYPE_DECDNS
#define ETHERTYPE_DECDNS 0x3c80
#endif
#ifndef ETHERTYPE_DECDTS
#define ETHERTYPE_DECDTS 0x3e80
#endif
#ifndef ETHERTYPE_VEXP
#define ETHERTYPE_VEXP 0x5b80
#endif
#ifndef ETHERTYPE_VPROD
#define ETHERTYPE_VPROD 0x5c80
#endif
#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK 0x9b80
#endif
#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP 0xf380
#endif
#ifndef ETHERTYPE_TIPC
#define ETHERTYPE_TIPC 0xca88
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x0081
#endif

/* see:
        https://en.wikipedia.org/wiki/IEEE_802.1Q
    and https://en.wikipedia.org/wiki/QinQ
*/
#ifndef ETHERTYPE_8021Q9100
#define ETHERTYPE_8021Q9100 0x0091
#endif
#ifndef ETHERTYPE_8021Q9200
#define ETHERTYPE_8021Q9200 0x0092
#endif
#ifndef ETHERTYPE_8021QinQ
#define ETHERTYPE_8021QinQ 0xa888
#endif
#ifndef ETHERTYPE_IPX
#define ETHERTYPE_IPX 0x3781
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0xdd86
#endif
#ifndef ETHERTYPE_PPP
#define ETHERTYPE_PPP 0x0b88
#endif
#ifndef ETHERTYPE_MPCP
#define ETHERTYPE_MPCP 0x0888
#endif
#ifndef ETHERTYPE_SLOW
#define ETHERTYPE_SLOW 0x0988
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS 0x4788
#endif
#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI 0x4888
#endif
#ifndef ETHERTYPE_PPPOED
#define ETHERTYPE_PPPOED 0x6388
#endif
#ifndef ETHERTYPE_PPPOES
#define ETHERTYPE_PPPOES 0x6488
#endif
#ifndef ETHERTYPE_NSH
#define ETHERTYPE_NSH 0x4F89
#endif
#ifndef ETHERTYPE_PPPOED2
#define ETHERTYPE_PPPOED2 0x123c
#endif
#ifndef ETHERTYPE_PPPOES2
#define ETHERTYPE_PPPOES2 0x133c
#endif
#ifndef ETHERTYPE_MS_NLB_HB
#define ETHERTYPE_MS_NLB_HB 0x6f88 /* MS Network Load Balancing Heartbeat */
#endif
#ifndef ETHERTYPE_JUMBO
#define ETHERTYPE_JUMBO 0x7088
#endif
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0xcc88
#endif
#ifndef ETHERTYPE_EAPOL
#define ETHERTYPE_EAPOL 0x8e88
#endif
#ifndef ETHERTYPE_RRCP
#define ETHERTYPE_RRCP 0x9988
#endif
#ifndef ETHERTYPE_AOE
#define ETHERTYPE_AOE 0xa288
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK 0x0090
#endif
#ifndef ETHERTYPE_VMAN
#define ETHERTYPE_VMAN 0x0091 /* Extreme VMAN Protocol */
#endif
#ifndef ETHERTYPE_CFM_OLD
#define ETHERTYPE_CFM_OLD 0xcdab /* 802.1ag depreciated */
#endif
#ifndef ETHERTYPE_CFM
#define ETHERTYPE_CFM 0x0289 /* 802.1ag */
#endif
#ifndef ETHERTYPE_IEEE1905_1
#define ETHERTYPE_IEEE1905_1 0x3a89 /* IEEE 1905.1 */
#endif
#ifndef ETHERTYPE_ISO
#define ETHERTYPE_ISO 0xfefe /* nonstandard - used in Cisco HDLC encapsulation */
#endif
#ifndef ETHERTYPE_CALM_FAST
#define ETHERTYPE_CALM_FAST 0x1111 /* ISO CALM FAST */
#endif
#ifndef ETHERTYPE_GEONET_OLD
#define ETHERTYPE_GEONET_OLD 0x0707 /* ETSI GeoNetworking (before Jan 2013) */
#endif
#ifndef ETHERTYPE_GEONET
#define ETHERTYPE_GEONET 0x4789 /* ETSI GeoNetworking (Official IEEE registration from Jan 2013) */
#endif
#ifndef ETHERTYPE_ARISTA
#define ETHERTYPE_ARISTA 0x8bd2 /*  Arista Networks vendor specific EtherType */
#endif
