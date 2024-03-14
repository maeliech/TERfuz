#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/libslirp.h"
#include "helper.h"

/* Structure for the fuzzers */
typedef struct pcap_hdr_s {
    guint32 magic_number; /* magic number */
    guint16 version_major; /* major version number */
    guint16 version_minor; /* minor version number */
    gint32 thiszone; /* GMT to local correction */
    guint32 sigfigs; /* accuracy of timestamps */
    guint32 snaplen; /* max length of captured packets, in octets */
    guint32 network; /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    guint32 ts_sec; /* timestamp seconds */
    guint32 ts_usec; /* timestamp microseconds */
    guint32 incl_len; /* number of octets of packet saved in file */
    guint32 orig_len; /* actual length of packet */
} pcaprec_hdr_t;

#ifdef CUSTOM_MUTATOR
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/// This is a custom mutator, this allows us to mutate only specific parts of
/// the input and fix the checksum so the packet isn't rejected for bad reasons.
extern size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                      size_t MaxSize, unsigned int Seed)
{
    uint8_t *Data_ptr = Data;
    uint8_t *ip_data;

    pcap_hdr_t *hdr = (void *)Data_ptr;
    pcaprec_hdr_t *rec = NULL;

    if (Size < sizeof(pcap_hdr_t)) {
        return 0;
    }
    Data_ptr += sizeof(*hdr);
    Size -= sizeof(*hdr);

    if (hdr->magic_number == 0xd4c3b2a1) {
        g_debug("FIXME: byteswap fields");
        return 0;
    } /* else assume native pcap file */
    if (hdr->network != 1) {
        return 0;
    }

    while (Size > sizeof(*rec)) {
        rec = (void *)Data_ptr;
        Data_ptr += sizeof(*rec);
        Size -= sizeof(*rec);
        if (rec->incl_len != rec->orig_len) {
            break;
        }
        if (rec->incl_len > Size) {
            break;
        }
        ip_data = Data_ptr + 14;
        uint8_t Data_to_mutate[MaxSize];
        uint8_t ip_hl = (ip_data[0] & 0xF);
        uint8_t ip_hl_in_bytes = ip_hl * 4;

        uint8_t *start_of_icmp = ip_data + ip_hl_in_bytes;
        uint16_t total_length =
            ntohs(*((uint16_t *)ip_data + 1)); // network order to host order
        uint16_t icmp_size =
            (total_length - ip_hl_in_bytes); /* total length -> is stored at the
                                                offset 2 in the header */

        // Copy interesting data to the `Data_to_mutate` array
        // here we want to fuzz everything in the ip header, maybe the IPs or
        // total length should be excluded ?
        memset(Data_to_mutate, 0, MaxSize);
        memcpy(Data_to_mutate, ip_data, ip_hl_in_bytes);

        // Call to libfuzzer's mutation function.
        // For now we dont want to change the header size as it would require to
        // resize the `Data` array to include the new bytes inside the whole
        // packet.
        // This should be easy as LibFuzzer probably does it by itself or
        // reserved enough space in Data beforehand, needs some research to
        // confirm.
        // FIXME: allow up to grow header size to 60 bytes,
        //      requires to update the `header length` before calculating
        //      checksum
        LLVMFuzzerMutate(Data_to_mutate, ip_hl_in_bytes, ip_hl_in_bytes);

        // Set the `checksum` field to 0 and calculate the new checksum
        Data_to_mutate[2] = 0;
        Data_to_mutate[3] = 0;
        uint16_t new_checksum =
            compute_checksum(Data_to_mutate, ip_hl_in_bytes);

        // Copy the mutated data back to the `Data` array and fix the checksum
        // value
        memcpy(ip_data, Data_to_mutate, ip_hl_in_bytes);
        *((uint16_t *)ip_data + 5) = new_checksum;

        Data_ptr += rec->incl_len;
        Size -= rec->incl_len;
    }

    return Size;
}
#endif // CUSTOM_MUTATOR
