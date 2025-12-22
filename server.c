#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include "udp_file_transfer.h"

void send_error_msg(int socket_fd, uint16_t error_code, const char *msg, const struct sockaddr_in *client_addr, socklen_t addr_len) 
{
    Packet_t err_packet = {0};
    err_packet.opcode = htons(OP_ERROR);
    err_packet.id = htons(error_code); 
    snprintf(err_packet.payload.error_msg, MAX_ERROR_MSG, "%s", msg);;// better then strncpy not adding unnessacery \0
    int err_len = HEADER_SIZE + strlen(err_packet.payload.error_msg) + 1;

    sendto(socket_fd, &err_packet, err_len, 0, (struct sockaddr *)client_addr, addr_len);
    
    printf("Sent Error %d: %s\n", error_code, msg);
}

void handle_rrq(int socketfd, struct sockaddr_in *client_addr, socklen_t client_len, Packet_t *msg_in) 
{
    printf("RRQ received for file %s\n", msg_in->payload.filename);
    FILE* file = fopen(msg_in->payload.filename, "rb");

    if (!file) {
        send_error_msg(socketfd, ERR_NOT_FOUND, "File not Found", client_addr, client_len);
        return;
    }

    uint16_t block_counter = 1;
    Packet_t data_packet = {0};
    Packet_t ack_packet = {0};
    data_packet.opcode = htons(OP_DATA);
    size_t bytes_read = 0;
    bool read_next = true;
    bool finish = false;

    while (1) {
        if (read_next) {
            bytes_read = fread(data_packet.payload.data, 1, MAX_PAYLOAD_SIZE, file);

            if (ferror(file)) {
                send_error_msg(socketfd, READDING_ERROR, "Reading file error", client_addr, client_len);
                break;
            }

            if (bytes_read < MAX_PAYLOAD_SIZE) {
                finish = true;
            }

            data_packet.id = htons(block_counter);
            read_next = false;
        }

        sendto(socketfd, &data_packet, bytes_read + HEADER_SIZE, 0, (struct sockaddr *)client_addr, client_len);

        ssize_t bytes_received = recvfrom(socketfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)client_addr, &client_len);
        if (bytes_received < 0) 
        {
            printf("Timeout! No ACK received for block %d. Resending...\n", block_counter);
            continue; 
        }
        if (bytes_received >= HEADER_SIZE) {
            if (ntohs(ack_packet.opcode) == OP_ACK) {
                if (ntohs(ack_packet.id) == block_counter) {
                    if (finish) {
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

void handle_wrq(int socketfd, struct sockaddr_in *client_addr, socklen_t client_len, Packet_t *msg_in) 
{
    printf("WRQ received for file %s\n", msg_in->payload.filename);
    FILE* check_exists = fopen(msg_in->payload.filename, "r");
    if (check_exists) {
        fclose(check_exists);
        send_error_msg(socketfd, 6, "File already exists - delete it first", client_addr, client_len);
        return;
    }

    FILE* file = fopen(msg_in->payload.filename, "wb");
    if (!file) 
    {
        send_error_msg(socketfd, 2, "Access violation or Disk full", client_addr, client_len);
        return;
    }
    
    Packet_t ack_packet = {0};
    uint16_t block_counter = 0;
    ack_packet.id = block_counter;
    ack_packet.opcode = OP_ACK;
    ssize_t bytes_received;
    Packet_t data_packet= {0};
    bool last_pack_received = false;

    while (1)
    {
        sendto(socketfd, &ack_packet, HEADER_SIZE, 0, (struct sockaddr *)client_addr, client_len);

        if (last_pack_received)
        {
            break;
        }

        bytes_received = recvfrom(socketfd, &data_packet, sizeof(data_packet), 0, (struct sockaddr *)client_addr, &client_len);
        
        if (bytes_received < 0) 
        {
            printf("Timeout! No DATA received for block %d. Resending ACK...\n", block_counter);            
            continue; 
        }

        if(data_packet.opcode == OP_DATA)
        {
            if(data_packet.id == block_counter + 1)
            {
                block_counter++;
                if(bytes_received < MAX_PAYLOAD_SIZE + HEADER_SIZE)//last pack
                {
                    last_pack_received = true;
                }
                //add htons 
                //wrtie to the file

            }
        }



    }
    








}

int main() {
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
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socketfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        printf("fail to bind");
        return 1;
    }

    Packet_t msg_in;
    struct sockaddr_in client_addr;
    socklen_t client_len;

    while (1) {
        client_len = sizeof(client_addr);
        ssize_t bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)&client_addr, &client_len);

        if (bytes_received > HEADER_SIZE) {
            uint16_t opcode = ntohs(msg_in.opcode);

            switch (opcode) {
                case 1: // RRQ
                    handle_rrq(socketfd, &client_addr, client_len, &msg_in);
                    break;

                case 2: // WRQ
                    handle_wrq(socketfd, &client_addr, client_len, &msg_in);
                    // handle_wrq will go here
                    break;

                default:
                    // Optional: send_error_msg for unknown opcode
                    break;
            }
        }
    }
    return 0;
}
