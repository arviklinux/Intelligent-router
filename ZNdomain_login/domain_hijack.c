/************************************************
author:arvik
description: Specify the domain name hijacking
email:1216601195@qq.com
date:2015/11/18
************************************************/

#include <linux/module.h>  
#include <linux/kernel.h>  
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
#include <linux/delay.h>

#include "forgeDNS.h"
#include "domain_map.h"

MODULE_LICENSE("GPL");

extern uint8_t localIP[4];
extern uint8_t localdm[64];

//UDP pseudo head, used for calibration
typedef struct
{
	unsigned long saddr;
	unsigned long daddr;
	char mbz;//mbz must be zero
	char protocal;
	unsigned short tcpl;//UDP(head+len)
}Fake_UDPheader;
 
 
static int adddata(struct sk_buff * skb); 
 
/**********************************
description: IP checksum
***********************************/
void IP_checksum(struct sk_buff * skb)
{
	unsigned long cksum = 0;
	struct iphdr *_ip;
	unsigned short *p_sum;	
	unsigned n = 0;
	
	_ip = ip_hdr(skb);
	p_sum = (uint16_t *)_ip;
	

	_ip->check = 0;
	n = _ip->ihl*4/2;
	while(n--)
	{
		cksum += *p_sum++;
	}
	cksum = (cksum&0x0000ffff) + (cksum>>16);
	_ip->check = (cksum&0x0000ffff);
	_ip->check = ~(_ip->check);		
}
 
/**********************************
description: IP checksum
***********************************/
void UDP_checksum(struct sk_buff * skb)
{
	uint32_t cksum = 0;
	struct iphdr *_ip;  
	struct udphdr *_udp;
	uint16_t *p_sum;
	uint16_t  n = 0;
	
	_ip = ip_hdr(skb);
	_udp = (struct udphdr *)(_ip+1);
	
	//12bytes UDP pseudo header	
	cksum = (_ip->saddr & 0x0000ffff) + (_ip->saddr>>16) + (_ip->daddr & 0x0000ffff) + (_ip->daddr>>16);
	cksum += htons(17) + _udp->len;
	cksum = (cksum&0x0000ffff) + (cksum>>16);
	
	cksum += _udp->source + _udp->dest + _udp->len + 0; 
	
	n = ntohs(_udp->len) - 8;
	p_sum = (uint16_t*)(_udp+1);
	for(; n>1; n=n-2)
	{
		cksum += *p_sum++;
	}
	if(1==n)
	{
		//cksum += (*p_sum) & 0xff00; 
		cksum += *(uint8_t*)p_sum;
	}
	
	cksum = (cksum&0x0000ffff) + (cksum>>16);
	cksum = (cksum&0x0000ffff) + (cksum>>16); 
	
	_udp->check = ~(cksum&0x0000ffff);
	
}

/**********************************
description: domain prase
***********************************/
int domain_prase(uint8_t *pos)
{
	int8_t d_buf[32];
	int8_t i = 0;
	
	memset(d_buf, 0, sizeof(d_buf));
	for(i = 0; pos[i]; i++) 
	{
		if(pos[i] < 20)
			d_buf[i] = '.';
		else
			d_buf[i] = pos[i];
		if(i>=31)
			return -1;
	}
	
	if(strnicmp(d_buf, localdm, strlen(localdm)) == 0)
	{
		printk("domain: %s	len: %d\n", d_buf, strlen(d_buf));
		return 1;       
	}
		
	return -1;
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

/**********************************
description: 
***********************************/
static unsigned int domain_hook(  
		unsigned int hooknum,  
		struct sk_buff * skb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn) (struct sk_buff *)) 
{
	struct iphdr *ip;
	struct udphdr *udp;
	uint8_t *p;
	
	if (!skb)  
        return NF_ACCEPT;
		
	
	if(skb->protocol != htons(0x0800)) //get ip data
		return NF_ACCEPT;
		
	ip = ip_hdr(skb);
	if(ip->protocol != 17) //get udp data
		return NF_ACCEPT;
	
	udp = (struct udphdr *)(ip+1);
	if( (udp != NULL) && (ntohs(udp->dest) != 53) ) //DNS req
	{
		return NF_ACCEPT;
	}
	

	p = (uint8_t *)udp + 8 + 12 + 1;
	if(domain_prase(p)>0)
	{	
		adddata(skb);
		UDP_checksum(skb);
		IP_checksum(skb);
		//printk("dest ip : %d.%d.%d.%d\n", NIPQUAD(ip->daddr));
		//printk("redirect to : %d.%d.%d.%d\n", NIPQUAD(ip->daddr));
	}
		
	return NF_ACCEPT; 
}

struct nf_hook_ops flow_ops = {  
	.list =  {NULL,NULL},  
	.hook = domain_hook,  
	.pf = PF_INET,   
	.hooknum = NF_INET_PRE_ROUTING, 
	.priority = NF_IP_PRI_FIRST+1
};

static int __init m_init(void)
{	
	init_dm_ip_moudle();
	nf_register_hook(&flow_ops);
		
	printk(" init ok\n");
	
	return 0;
}

static void __exit m_exit(void)
{	
	nf_unregister_hook(&flow_ops);
	exit_dm_ip_moudle();
	printk("exit domain_hijack\n");
}

module_init(m_init);  
module_exit(m_exit); 

/**********************************
description: dns respone data
***********************************/
int8_t D_name[] = 
{
0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x04, 0x0a, 0x0a, 0x0a, 0xfe
};

/**********************************
description: forge dns respone data
***********************************/
static int adddata(struct sk_buff * skb)
{
	struct iphdr *ip = NULL;
	struct udphdr *udp = NULL;
	uint8_t *p = NULL;
	uint16_t *p_data = NULL;
	uint16_t tmpdata = 0;
	uint32_t tmpip = 0;
	uint8_t i = 0 , tmp = 0;
	
	
	memcpy(&D_name[sizeof(D_name)-4], localIP, 4); //IP
	
	p = skb_put(skb, sizeof(D_name));
	if(NULL != p)
		memcpy(p, D_name, sizeof(D_name));
		
	//
	ip = ip_hdr(skb);
	udp = (struct udphdr *)(ip+1);
	
	//DNS
	p_data = (uint16_t *)(udp + 1);
	p_data[1] = htons(0x8580); //FLAGS
	p_data[3] = htons(1); //AuswerRRs
	
	//UDP
	tmpdata = udp->source; 
	udp->source = udp->dest;
	udp->dest = tmpdata;
	udp->len = htons(ntohs(udp->len) + sizeof(D_name)); 
	
	//IP
	ip->tot_len = htons(ntohs(ip->tot_len) + sizeof(D_name));
	ip->id = 0x0000; //IP id
	ip->frag_off = htons(0x4000);
	tmpip = ip->saddr; 
	ip->saddr = ip->daddr;
	ip->daddr = tmpip;
	
    //eth header
	if(skb->mac_header == NULL)
	{
		printk("counterfeit dns data fail! error: skb->mac_header is NULL!\n");
		return -1;
	}
	//
	for(i = 0; i<6; i++)
	{
		tmp = skb->mac_header[i];
		skb->mac_header[i] = skb->mac_header[i+6];
		skb->mac_header[i+6] = tmp;
	}
	//ok,the rest of work is checksum
	printk("counterfeit DNS success!\n");
	return 1;
}




