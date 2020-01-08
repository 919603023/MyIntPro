#include <stdio.h>
#include <stdlib.h>
#include<string.h>
typedef struct Route_MsgNode
{

    unsigned char Route_Ip[4]; //目的IP地址

    unsigned char Route_Netmask[4]; //子网掩码

    unsigned char Route_NextHop[4]; //下一跳，发向下一个IP指向的网段

    struct Route_MsgNode *front;

    struct Route_MsgNode *next;

} CONFIG_ROUTE_MSG;
int ReadFile()
{
    CONFIG_ROUTE_MSG *Route_temp = (CONFIG_ROUTE_MSG *)malloc(sizeof(CONFIG_ROUTE_MSG));
    char text[500] = {0};
    char *FileName = "Config_Route_Msg";
    FILE *fp;
    if ((fp = fopen(FileName, "r")) == NULL)
    {
        perror("fail to fopen");
        return -1;
    }
    while (1)
    {

        if (fgets(text, 500, fp) == NULL)
        {
            break;
        }
        else if (strchr(text, '#') != NULL)
        {
            continue;
        }
        if (strncmp(text, "{",1) == 0)
        {
           while (1)
           {
               unsigned char buf[4];
              unsigned  char buff[100];
               if (fgets(text, 500, fp) == NULL)
                {
                 break;
                 }
               
               
            if (strncmp(text, "Route_Ip",8) ==0)
            {
                sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);
                
            }
            else if (strncmp(text, "Route_Netmask",13) ==0)
            {
                sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);

            }
            else if (strncmp(text, "Route_NextHop",13) ==0)
            {
                sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);
            }
            else if (strchr(text, '#') != NULL)
        {
            continue;
        }
            else
            {
            if (strchr(text, '}') != NULL)
            {
               break; 
            }
            }
            
                 for(int i = 0 ;i < 4 ;i++)
                {
                    printf("%d.",buf[i]);
                }
                    printf("\n");
           }
            
           
        }
    }
}
int main()
{
    ReadFile();
}