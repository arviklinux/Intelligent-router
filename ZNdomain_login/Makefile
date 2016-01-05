#************************************************
#author:arvik
#description: Specify the domain name hijacking
#email:1216601195@qq.com
#date:2015/11/18
#************************************************

#CC=gcc
CC=/opt/buildroot-gcc342/bin/mipsel-linux-gcc



MODULE_NAME := ZNdomain_login

#KERNELBUILD:=/usr/src/kernels/$(shell uname -r) 
KERNELBUILD:=/root/study/MTK3/MTK_source/linux-2.6.36.x

default:   
	make -C $(KERNELBUILD) M=$(shell pwd)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := domain_hijack.o forgeDNS.o domain_map.o
	
domain_hijack.o:domain_hijack.c
	$(CC) -o -D_GUN_SOURCE -std=c99 $@ domain_hijack.c 
	
forgeDNS.o:forgeDNS.c
	$(CC) -o -D_GUN_SOURCE -std=c99 $@ forgeDNS.c
	
domain_map.o:domain_map.c
	$(CC) -o -D_GUN_SOURCE -std=c99 $@ domain_map.o
	
clean:  
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions 
