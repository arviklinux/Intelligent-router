/************************************************
author:arvik
description: Specify the domain name hijacking
email:1216601195@qq.com
date:2015/11/18
************************************************/

#include <linux/init.h>  
#include <linux/types.h>  
#include <linux/netdevice.h>  
#include <linux/skbuff.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/inet.h>  
#include <linux/in.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/string.h>
 

#include "forgeDNS.h"

//DNS
typedef struct _resDNS_hdr
{
	uint16_t trans_ID;
	uint16_t flags;
	uint16_t Questions;
	uint16_t AuswerRRs;
	uint16_t AuthorityRRS;
	uint16_t AdditionRRS;
	int8_t Answers[];
}resDNS_hdr;


//
typedef struct
{
	uint16_t Name;
	uint16_t Type;
	uint16_t Class;
	uint32_t TimeToLive;
	uint16_t DataLength;
	u_IP reIP;
}DNSname;


