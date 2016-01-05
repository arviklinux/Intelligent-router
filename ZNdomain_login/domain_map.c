/************************************************
author:arvik
description: Specify the domain name hijacking
email:1216601195@qq.com
date:2015/11/18
************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h> 
#include <linux/proc_fs.h>
#include <asm/uaccess.h> 
#include <asm/errno.h>

//
static struct proc_dir_entry *proc_entry; 
static struct proc_dir_entry *flow_root;

uint8_t localIP[4]={0x0a, 0x0a, 0x0a, 0xfe}; //IP
uint8_t localdm[64]="mydomain.com"; //domain

static int dm_ip_read(char *page,char **start,off_t off, int count ,int *eof,void *data)
{
	int len = 0;
	
	len = sprintf(page, "%s	%d.%d.%d.%d\n", localdm, localIP[0], localIP[1], localIP[2], localIP[3]);
	
	if(off > len)
	{
		return 0;
	}
	
	if(count > len-off)
	{
		count = len - off;
		*eof = 1;
	}
	
	*start = page + off;
	
	//*eof = 1;
	return count;
}

void str__(int8_t *p)
{	
	while(*p++)
	{
		if(*p == '.')
			*p = ' ';
	}
}

/******************
return: the count that be written success 
note: don't return 0, thus system will enter into bad loop 
*******************/
int dm_ip_write(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	int8_t buf[64];
	int8_t tmpbuf1[8], tmpbuf2[60] = {0};
	int len = 0;
	int err = 1;
	
	memset(buf, 0, sizeof(buf));
	memset(tmpbuf1, 0, sizeof(tmpbuf1));
	//
	
	len = sizeof(buf)-1;
	if(count<len)
		len = count;

	if(copy_from_user(buf, buffer, len))
	{
		printk("dm_ip_write fail!\n");
		goto result;
	}
	
	err = sscanf(buf, "%s %s", tmpbuf1, tmpbuf2);

	
	
	if(strnicmp(tmpbuf1, "ip", strlen("ip")) == 0)
	{
		//ip
		uint16_t a, b, c, d;
		str__(tmpbuf2);
		err = sscanf(tmpbuf2, "%d %d %d %d", &a, &b, &c, &d);
		if(err>0)
		{
			localIP[0] = a & 0x00ff;
			localIP[1] = b & 0x00ff;
			localIP[2] = c & 0x00ff;
			localIP[3] = d & 0x00ff;
		}
		
	}
	else if(strnicmp(tmpbuf1, "dm", strlen("dm")) == 0)
	{
		//domain
		memcpy(localdm, tmpbuf2, strlen(tmpbuf2)+1);
	}
	
result:
	return len;
}

/**********************************
description: make a folder and a file, and appoint callback function write and read
***********************************/
int init_dm_ip_moudle(void)
{
	int ret = 0;
	
	flow_root = proc_mkdir("router_domain", NULL);
	if(flow_root == NULL)
	{
		printk("create dir router_domain fail\n");
		return -1;
	}
	

	proc_entry = create_proc_entry("dm_ip", 0444, flow_root); 
	if(proc_entry==NULL) 
	{
		printk("fortune :couldn't create proc entry\n");
		ret = -2;
		
		return ret;
	}  
	proc_entry->read_proc = dm_ip_read;
	proc_entry->write_proc = dm_ip_write;
	

	return ret;
}


void exit_dm_ip_moudle(void)
{	
	remove_proc_entry("dm_ip", flow_root);   
    remove_proc_entry("router_domain", NULL); 
}


