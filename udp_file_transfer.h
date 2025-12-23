#include <stdint.h>

#define SERVER_PORT     6969    
#define MAX_PAYLOAD_SIZE 512    
#define MAX_FILENAME    256     
#define MAX_ERROR_MSG   128  
#define HEADER_SIZE 4
#define MAX_RESENDING 5

#define OP_RRQ    1  // Read Request
#define OP_WRQ    2  // Write Request
#define OP_DATA   3  // Data 
#define OP_ACK    4  // Acknowledgment
#define OP_ERROR  5  // Error
#define OP_DELETE 6  // Delete

#define ERR_NOT_FOUND     1  
#define ERR_ACCESS_DENIED 2 
#define ERR_DISK_FULL     3  
#define ERR_ILLEGAL_OP    4  
#define ERR_FILE_EXISTS   5
#define READDING_ERROR    6
#define ERR_ATTEMPTS_EXCEEDED 7
#define ERR_DELETING 8

typedef struct
{
   uint16_t opcode;
   uint16_t id;
   union 
   {
    char data[MAX_PAYLOAD_SIZE];
    char filename[MAX_FILENAME];
    char error_msg[MAX_ERROR_MSG];
   } payload;
} __attribute__((packed)) Packet_t;
