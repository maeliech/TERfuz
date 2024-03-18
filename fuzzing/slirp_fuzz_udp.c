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
    size_t i, current_size = Size;
    uint8_t *Data_ptr = Data;
    uint8_t *ip_data;

    pcap_hdr_t *hdr = (void *)Data_ptr;
    pcaprec_hdr_t *rec = NULL;

    if (current_size < sizeof(pcap_hdr_t)) {
        return 0;
    }

    Data_ptr += sizeof(*hdr);
    current_size -= sizeof(*hdr);

    if (hdr->magic_number == 0xd4c3b2a1) {
        g_debug("FIXME: byteswap fields");
        return 0;
    } /* else assume native pcap file */
    if (hdr->network != 1) {
        return 0;
    }

    while (current_size > sizeof(*rec)) {
        rec = (void *)Data_ptr;
        Data_ptr += sizeof(*rec);
        current_size -= sizeof(*rec);

        if (rec->incl_len != rec->orig_len) {
            break;
        }
        if (rec->incl_len > current_size) {
            break;
        }
        ip_data = Data_ptr + 14;

        // Exclude packets that are not UDP from the mutation strategy
        if (ip_data[9] != IPPROTO_UDP) {
            Data_ptr += rec->incl_len;
            current_size -= rec->incl_len;
            continue;
        }
        // Allocate a bit more than needed, this is useful for
        // checksum calculation.
        uint8_t Data_to_mutate[MaxSize + 12];
        uint8_t ip_hl = (ip_data[0] & 0xF);
        uint8_t ip_hl_in_bytes = ip_hl * 4;

        uint8_t *start_of_udp = ip_data + ip_hl_in_bytes;
        uint16_t udp_size = ntohs(*((uint16_t *)start_of_udp + 2));

        // The size inside the packet can't be trusted, if it is too big it can
        // lead to heap overflows in the fuzzing code.
        // Fixme : don't use udp_size inside the fuzzing code, maybe use the
        //         rec->incl_len and manually calculate the size.
        if (udp_size >= MaxSize || udp_size >= rec->incl_len) {
            Data_ptr += rec->incl_len;
            current_size -= rec->incl_len;
            continue;
        }

        // Copy interesting data to the `Data_to_mutate` array
        // here we want to fuzz everything in the udp packet
        memset(Data_to_mutate, 0, MaxSize + 12);
        memcpy(Data_to_mutate, start_of_udp, udp_size);

        // Call to libfuzzer's mutation function.
        // Pass the whole UDP packet, mutate it and then fix checksum value
        // so the packet isn't rejected.
        // The new size of the data is returned by LLVMFuzzerMutate.
        // Fixme: allow to change the size of the UDP packet, this will require
        //     to fix the size before calculating the new checksum and change
        //     how the Data_ptr is advanced.
        //     Most offsets bellow should be good for when the switch will be
        //     done to avoid overwriting new/mutated data.
        size_t mutated_size =
            LLVMFuzzerMutate(Data_to_mutate, udp_size, udp_size);

        // Set the `checksum` field to 0 to calculate the new checksum
        *((uint16_t *)Data_to_mutate + 3) = (uint16_t)0;
        // Copy the source and destination IP addresses, the UDP length and
        // protocol number at the end of the `Data_to_mutate` array to calculate
        // the new checksum.
        for (i = 0; i < 4; i++) {
            *(Data_to_mutate + mutated_size + i) = *(ip_data + 12 + i);
        }
        for (i = 0; i < 4; i++) {
            *(Data_to_mutate + mutated_size + 4 + i) = *(ip_data + 16 + i);
        }

        *(Data_to_mutate + mutated_size + 8) = *(start_of_udp + 4);
        *(Data_to_mutate + mutated_size + 9) = *(start_of_udp + 5);
        // The protocol is a uint8_t, it follows a 0uint8_t for checksum
        // calculation.
        *(Data_to_mutate + mutated_size + 11) = IPPROTO_UDP;

        uint16_t new_checksum =
            compute_checksum(Data_to_mutate, mutated_size + 12);
        *((uint16_t *)Data_to_mutate + 3) = new_checksum;

        // Copy the mutated data back to the `Data` array
        memcpy(start_of_udp, Data_to_mutate, mutated_size);

        Data_ptr += rec->incl_len;
        current_size -= rec->incl_len;
    }
    return Size;
}
#endif // CUSTOM_MUTATOR
