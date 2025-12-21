#include <stdint.h>

typedef struct
{
   uint16_t opcode;
   uint16_t id;
   union 
   {
    char data[2048];
    char filename[2048];
    char error_msg[2048];
   } payload;
} __attribute__((packed)) Packet_t;
