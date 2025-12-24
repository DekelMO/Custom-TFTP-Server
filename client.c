#include <stdio.h>

#include "udp_file_transfer.h"

int main()
{
    printf("Hey\n");
    while(1)
    {
        uint8_t op_input = 0;
        printf("Please choose the operation you whould like to perform\n1 - read file from the server\n2 - write file to server\n3 - delete file from server");
        char file_name[FILENAME_MAX] = {0};
        scanf("%d",&op_input);
        if(op_input == 3)
            op_input = OP_DELETE;
        printf("Please insert the full file name");
        scanf("%s", file_name);
        //need to flush out ectra chars??????
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