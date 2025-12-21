#include <stdint.h>

typedef struct
{
   uint16_t opcode;
   uint16_t id;
   char data[2048];

} __attribute__((packed)) Packet_t;
