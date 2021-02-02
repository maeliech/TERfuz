#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

uint16_t ip_header_checksum(uint8_t *Data, size_t Size);