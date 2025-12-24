#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "udp_file_transfer.h"
void handle_rrq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, const char* filename) 
{

}
void handle_wrq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, const char* filename) 
{

}
void handle_drq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, const char* filename)
{

}

int main()
{

    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd == -1) {
        printf("couldnt get socket");
        return 1;
    }
    struct timeval tv;
    tv.tv_sec = 3;      
    tv.tv_usec = 0;
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting timeout");    
    }
    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    socklen_t servaddr_len = sizeof(servaddr);



    printf("Hey\n");
    while(1)
    {
        int op_input = 0;
        printf("Please choose the operation you whould like to perform\n1 - read file from the server\n2 - write file to server\n3 - delete file from server");
        char file_name[FILENAME_MAX] = {0};
        scanf("%d",&op_input);
        while (getchar() != '\n');
        if(op_input == 3)
            op_input = OP_DELETE;
        printf("Please insert the full file name");
        if (fgets(file_name, sizeof(file_name), stdin) != NULL) 
        {
            char *newline = strchr(file_name, '\n');    
            if (newline != NULL) {
                *newline = '\0';
            } else {
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
                printf("Warning: Filename was too long and was truncated.\n");
            }
        }
        switch (op_input)
        {
        case OP_RRQ:
            /* code */
            break;
        case OP_WRQ:
            /* code */
            break;
        case OP_DELETE:
            /* code */
            break;
        
        default:
            break;
        }

    }
}