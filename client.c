#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/md5.h> // For MD5 checksum
#include <openssl/aes.h> // For AES encryption

#include "udp_file_transfer.h"

// Helper for AES Encryption/Decryption
void aes_process(const char *in, char *out, size_t len, uint16_t block_id, int enc) {
    AES_KEY key;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);
    snprintf((char*)iv, AES_BLOCK_SIZE, "%016d", block_id); 

    AES_set_encrypt_key((const unsigned char*)AES_KEY_STR, 128, &key);
    int num = 0;
    AES_cfb128_encrypt((const unsigned char*)in, (unsigned char*)out, len, &key, iv, &num, enc ? AES_ENCRYPT : AES_DECRYPT);
}

void client_send_error(int socket_fd, uint16_t error_code, const char *msg, const struct sockaddr_in *servaddr, socklen_t servaddr_len) 
{
    Packet_t err_packet = {0};
    err_packet.opcode = htons(OP_ERROR);
    err_packet.id = htons(error_code); 
    snprintf(err_packet.payload.error_msg, MAX_ERROR_MSG, "%s", msg);
    int err_len = HEADER_SIZE + strlen(err_packet.payload.error_msg) + 1;
    sendto(socket_fd, &err_packet, err_len, 0, (struct sockaddr *)servaddr, servaddr_len);
}

// Helper: Calculate MD5 checksum of a file
void calc_md5(const char* filename, unsigned char* md5_result) {
    FILE* file = fopen(filename, "rb");
    if (!file) { memset(md5_result, 0, MD5_DIGEST_LENGTH); return; }
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    unsigned char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        MD5_Update(&md5_ctx, buf, n);
    }
    MD5_Final(md5_result, &md5_ctx);
    fclose(file);
}

// Helper: Print MD5 as hex
void print_md5(const unsigned char* md5) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) printf("%02x", md5[i]);
}

void handle_rrq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, Packet_t *first_msg, ssize_t first_len, const char* filename) 
{
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Could not open local file for writing");
        return;
    }
    Packet_t msg_in = *first_msg;
    ssize_t bytes_received = first_len;
    Packet_t ack_packet = {0};
    uint16_t expected_block = 1;
    char decrypted_data[MAX_PAYLOAD_SIZE];

    while (1) {
        uint16_t opcode = ntohs(msg_in.opcode);
        uint16_t block_id = ntohs(msg_in.id);
        if (opcode == OP_ERROR) {
            printf("Server returned error: %s (Code: %d)\n", msg_in.payload.error_msg, block_id);
            break;
        }
        if (opcode == OP_DATA && block_id == expected_block) {
            size_t data_len = bytes_received - HEADER_SIZE;
            
            // Decrypt data
            aes_process(msg_in.payload.data, decrypted_data, data_len, block_id, 0);
            
            fwrite(decrypted_data, 1, data_len, file);
            ack_packet.opcode = htons(OP_ACK);
            ack_packet.id = htons(block_id);
            sendto(socketfd, &ack_packet, HEADER_SIZE, 0, (struct sockaddr *)servaddr, servaddr_len);
            if (data_len < MAX_PAYLOAD_SIZE) {
                printf("Download of '%s' complete.\n", filename);
                break;
            }
            expected_block++;
        }
        bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)servaddr, &servaddr_len);
        if (bytes_received < 0) {
            printf("Timeout waiting for block %d\n", expected_block);
            break;
        }
    }
    fclose(file);
    // Calculate and print MD5 checksum
    unsigned char md5[MD5_DIGEST_LENGTH];
    calc_md5(filename, md5);
    printf("MD5 of downloaded file: "); print_md5(md5); printf("\n");
}

void handle_wrq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, Packet_t *first_msg, const char* filename) 
{
    if (ntohs(first_msg->opcode) != OP_ACK || ntohs(first_msg->id) != 0) {
        if (ntohs(first_msg->opcode) == OP_ERROR)
            printf("Server error: %s\n", first_msg->payload.error_msg);
        return;
    }
    FILE* file = fopen(filename, "rb");
    if (!file) {
        client_send_error(socketfd, ERR_NOT_FOUND, "File not found locally", servaddr, servaddr_len);
        return;
    }
    uint16_t block_counter = 1;
    Packet_t data_packet = {0};
    Packet_t ack_in = {0};
    bool finish = false;
    char raw_buffer[MAX_PAYLOAD_SIZE];

    while (1) {
        size_t bytes_read = fread(raw_buffer, 1, MAX_PAYLOAD_SIZE, file);
        
        // Encrypt data
        aes_process(raw_buffer, data_packet.payload.data, bytes_read, block_counter, 1);

        data_packet.opcode = htons(OP_DATA);
        data_packet.id = htons(block_counter);
        if (bytes_read < MAX_PAYLOAD_SIZE) finish = true;
        uint8_t retries = 0;
        while (retries <= MAX_RESENDING) {
            sendto(socketfd, &data_packet, bytes_read + HEADER_SIZE, 0, (struct sockaddr *)servaddr, servaddr_len);
            ssize_t res = recvfrom(socketfd, &ack_in, sizeof(ack_in), 0, (struct sockaddr *)servaddr, &servaddr_len);
            if (res >= HEADER_SIZE && ntohs(ack_in.opcode) == OP_ACK && ntohs(ack_in.id) == block_counter) {
                break;
            }
            retries++;
            printf("Timeout for ACK %d, retrying (%d/%d)...\n", block_counter, retries, MAX_RESENDING);
        }
        if (retries > MAX_RESENDING) {
            printf("Failed to get ACK for block %d after max retries.\n", block_counter);
            break;
        }
        if (finish) break;
        block_counter++;
    }
    fclose(file);
    printf("Upload of '%s' complete.\n", filename);
    // Calculate and print MD5 checksum
    unsigned char md5[MD5_DIGEST_LENGTH];
    calc_md5(filename, md5);
    printf("MD5 of uploaded file: "); print_md5(md5); printf("\n");
}

void handle_drq(int socketfd, struct sockaddr_in *servaddr, socklen_t servaddr_len, Packet_t *first_msg)
{
    if (ntohs(first_msg->opcode) == OP_ACK) {
        printf("File deleted successfully from server.\n");
    } else if (ntohs(first_msg->opcode) == OP_ERROR) {
        printf("Server error on delete: %s (Code: %d)\n", first_msg->payload.error_msg, ntohs(first_msg->id));
    }
}

int main()
{
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd == -1) { perror("socket"); return 1; }

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    Packet_t msg_in, msg_out;
    printf("TFTP Client Started\n");

    while(1) {
        memset(&msg_out, 0, sizeof(msg_out));
        printf("\nChoose operation: 1-Read, 2-Write, 3-Delete, 0-Exit: ");
        int choice;
        if (scanf("%d", &choice) != 1) break;
        while (getchar() != '\n');
        if (choice == 0) break;

        uint16_t op_type = (choice == 1) ? OP_RRQ : (choice == 2) ? OP_WRQ : (choice == 3) ? OP_DELETE : 0;
        if (op_type == 0) continue;

        printf("Enter filename: ");
        if (fgets(msg_out.payload.filename, MAX_FILENAME, stdin) == NULL) continue;
        msg_out.payload.filename[strcspn(msg_out.payload.filename, "\n")] = 0;

        msg_out.opcode = htons(op_type);
        msg_out.id = htons(0);

        // Handshake - ניסיון תקשורת ראשוני
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t bytes_received = -1;
        uint8_t attempts = 0;

        while (attempts <= MAX_RESENDING) {
            sendto(socketfd, &msg_out, strlen(msg_out.payload.filename) + HEADER_SIZE + 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("Waiting for server response...\n");
            bytes_received = recvfrom(socketfd, &msg_in, sizeof(msg_in), 0, (struct sockaddr *)&from_addr, &from_len);
            if (bytes_received >= 0) break;
            attempts++;
        }

        if (bytes_received < 0) {
            printf("Server not responding.\n");
            continue;
        }

    
        switch (op_type) {
            case OP_RRQ: 
                handle_rrq(socketfd, &from_addr, from_len, &msg_in, bytes_received, msg_out.payload.filename); 
                break;
            case OP_WRQ: 
                handle_wrq(socketfd, &from_addr, from_len, &msg_in, msg_out.payload.filename); 
                break;
            case OP_DELETE: 
                handle_drq(socketfd, &from_addr, from_len, &msg_in);   
                break;
        }
    }
    close(socketfd);
    return 0;
}