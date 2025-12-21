#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "udp_file_transfer.h"



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
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(socketfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("fail to bind");
        return 1;
    }

    Packet_t msg_in;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    while(1)
    {
        ssize_t bytes_received;
        client_len = sizeof(client_addr);
        bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)&client_addr, &client_len);
        if (bytes_received > HEADER_SIZE)// received msg and its not empty
        {
            uint16_t opcode = ntohs(msg_in.opcode);
            uint16_t id = ntohs(msg_in.id);

            switch (opcode)
            {
            case 1: // RRQ
                printf("RRQ received for file %s\n", msg_in.payload.filename);
                FILE* file = fopen(msg_in.payload.filename, "rb");
                if(!file)
                {
                    Packet_t err_packet;
                    memset(&err_packet, 0, sizeof(err_packet));
                    err_packet.opcode = htons(OP_ERROR);
                    err_packet.id = htons(ERR_NOT_FOUND); 
                    strncpy(err_packet.payload.error_msg, "File not Found", MAX_ERROR_MSG - 1);
                    err_packet.payload.error_msg[MAX_ERROR_MSG - 1] = '\0';
                    
                    int err_len = HEADER_SIZE + strlen(err_packet.payload.error_msg) + 1;
                    sendto(socketfd, &err_packet, err_len, 0, (struct sockaddr *)&client_addr, client_len);
                    perror("File not found");
                }
                else
                {
                    uint16_t block_counter = 1;
                    Packet_t data_packet;
                    data_packet.opcode = htons(OP_DATA);
                    size_t bytes_read = 0;
                    bool read_next = true;
                    bool finish = false;

                    while(1)
                    {
                        if(read_next)
                        {
                            bytes_read = fread(data_packet.payload.data, 1, MAX_PAYLOAD_SIZE, file);
                            
                            if (ferror(file))
                            {
                                Packet_t err_packet;
                                err_packet.opcode = htons(OP_ERROR);
                                err_packet.id = htons(READDING_ERROR); 
                                strncpy(err_packet.payload.error_msg, "Reading file error", MAX_ERROR_MSG - 1);
                                err_packet.payload.error_msg[MAX_ERROR_MSG - 1] = '\0';
                                
                                int err_len = HEADER_SIZE + strlen(err_packet.payload.error_msg) + 1;
                                sendto(socketfd, &err_packet, err_len, 0, (struct sockaddr *)&client_addr, client_len);
                                break; 
                            }

                            if (bytes_read < MAX_PAYLOAD_SIZE)
                            {
                                finish = true;
                            }

                            data_packet.id = htons(block_counter);
                            read_next = false; 
                        }

                        sendto(socketfd, &data_packet, bytes_read + HEADER_SIZE, 0, (struct sockaddr *)&client_addr, client_len);
                        
                        bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)&client_addr, &client_len);
                        
                        if (bytes_received >= HEADER_SIZE)
                        {
                            if (ntohs(msg_in.opcode) == OP_ACK)
                            {
                                if (ntohs(msg_in.id) == block_counter)
                                {
                                    if (finish)
                                    {
                                        break; 
                                    }
                                    block_counter++;
                                    read_next = true;
                                }
                            }
                        }
                    }
                    fclose(file);
                    printf("Transfer finished.\n");
                }
                break;
            case 2://WRQ
                printf("WRQ received for file %s\n", msg_in.payload.filename);
                handle_wrq(socketfd, &client_addr, client_len, &msg_in);
                break;
            case 3://DATA
                /* code */
                break;
            case 4://ACK
                /* code */
                break;
            case 5://ERROR
                /* code */
                break;
            case 6://DELETE
                /* code */
                break;
            
            default:
                break;
            }

        }
    }



}
