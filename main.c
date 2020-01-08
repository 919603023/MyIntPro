#include "fun.h"

int main()
{
	ReadConfig_Route_MsgFile();
	getinterface(); // 获取自身网卡信息

	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	printf("fd = %d\n", fd);
	CONFIG_ROUTE_MSG *head = Route_Msg;
	if (head != NULL)
		
	while (head != NULL)
	{

		for (int i = 0; i < 4; i++)
		{
			printf("%d.", head->Route_Ip[i]);
		}
		printf("\n");
		for (int i = 0; i < 4; i++)
		{
			printf("%d.", head->Route_Netmask[i]);
		}
		printf("\n");
		for (int i = 0; i < 4; i++)
		{
			printf("%d.", head->Route_NextHop[i]);
		}
		printf("\n");
		if (head->next == NULL)
			break;
	}

	while (1)
	{

		unsigned char buf[1500] = "";

		int len = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);

		if (AnalyzeAgreement(buf) == -1)
		{
			continue;
		}

		if (mybuf.type == ARP_BACK)
		{
				//如果是ARP请求，使用函数查看是否有该IP的记录，
                        //如果没有该IP的记录，则使用插入节点函数，插入节点
                         //如果返回0证明列表插进去了，如果是1证明查到了ARP记录
			if (ArpDispose(mybuf.src_ip, NULL, mybuf.dst_mac, INSERT) == -1)
			{
				continue;
			}

				
		}
		//是否是同一网段
		int Ethnum;

		Ethnum = IsSameSegment();
		
		//有同一网段，返回所出去的网卡
		if (Ethnum == -1)
		{
			//没有同一网段
			//路由表查表
			Ethnum = Config_Route_MsgDispose(mybuf.dst_ip, NULL, NULL, INSERT);
			if (Ethnum == -1)
			{
				unsigned char buf[100];
				sprintf(buf,"目的IP：%d,%d,%d,%d",mybuf.dst_ip[0],mybuf.dst_ip[1],mybuf.dst_ip[2],mybuf.dst_ip[3]);
				printf("%s\n",buf);
				continue;
			}
			//路由表有同一网段，返回所出去的网卡

			
		}

		

		//查ARP表
		//查ARP表
                 //如果查到，将目的buf中的目的mac赋值为此IP的mac
                //如果查不到，应该发送ARP请求，并跳过本次循环
		if (ArpDispose(mybuf.dst_ip, NULL, mybuf.dst_mac, FIND) == -1)
		{
			SendArp(Ethnum,0,fd,NULL);
			continue;
		}
		

			memcpy(buf, mybuf.dst_mac, 6);
			memcpy(buf + 6, net_interface[Ethnum].mac, 6);
			SendTo(len, buf, Ethnum, fd);
			printf("%s\n",net_interface[Ethnum].name);
			

		  bzero(&mybuf, sizeof(mybuf));
	}
	close(fd);
	return 0;
}
