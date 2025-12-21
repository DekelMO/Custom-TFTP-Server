#include "udp_file_transfer.h"
#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);//creating a socket 
    if (socketfd == -1){
        printf("couldnt get socket");
        return 1;
    } 
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));//rest garb values
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(6969);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(socketfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("fail to bind");
        return 1;
    }

    Packet_t msg_in;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while(1)
    {
        ssize_t bytes_received;
        bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)&client_addr, &client_len);
    }



}
