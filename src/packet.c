#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "packet.h"

#define MAX_8 (0xFF)
#define MAX_16 (0xFFFF)

#define MIN_IP_HEADER_LENGTH (20)
#define MIN_TCP_HEADER_LENGTH (20)
#define MIN_UDP_HEADER_LENGTH (8)

/* Transport layer header types */
enum {TCP = 6, UDP = 17};

uint8_t get_8_bits (uint8_t, int, int);
uint16_t get_16_bits (uint16_t, int, int);

void parse_packet (packet_t *packet, int data_link_offset, void *raw, int raw_length)
{
  packet->valid = false;

  if (raw_length < data_link_offset)
  {
    fprintf (stderr, "Packet is shorter than data link offset\n"); fflush (stderr);
    return;
  }

  raw += data_link_offset;
  raw_length -= data_link_offset;

  ip_header_t *ip_header = NULL;
  tcp_header_t *tcp_header = NULL;
  udp_header_t *udp_header = NULL;

  assert (sizeof (ip_header_t) == MIN_IP_HEADER_LENGTH);

  if (raw_length < MIN_IP_HEADER_LENGTH)
  {
    fprintf (stderr, "Packet is shorter than min IP header length\n"); fflush (stderr);
    return;
  }

  ip_header = (ip_header_t *) raw;

  /* Copy IP version */
  uint8_t version = get_8_bits (ip_header->version_and_ihl, 1, 4);
  packet->version = version;
  /* ---------------- */

  /* Copy IP header length and check with raw length */
  uint8_t ihl = get_8_bits (ip_header->version_and_ihl, 5, 8); /* number of words */
  uint8_t ip_header_length = ihl * (uint8_t) sizeof (uint32_t); /* number of bytes */
  if (raw_length < ip_header_length)
  {
    fprintf (stderr, "Packet is shorter than actual IP header length\n"); fflush (stderr);
    return;
  }
  packet->ip_header_length = ip_header_length;
  /* ----------------------------------------- */

  /* Copy type of service */
  packet->type_of_service = ip_header->type_of_service;
  /* -------------------- */

  /* Copy fragmentation offset */
  uint16_t frag_offset = get_16_bits (ntohs (ip_header->flags_and_frag_os), 4, 16);
  packet->frag_offset = frag_offset;
  /* ------------------------- */

  /* Check and copy protocol */
  if (ip_header->protocol == TCP)
  {
    strcpy (packet->transport_protocol, "tcp");
  }
  else if (ip_header->protocol == UDP)
  {
    strcpy (packet->transport_protocol, "udp");
  }
  else
  {
    fprintf (stderr, "Packet's transport protocol is neither TCP nor UDP\n"); fflush (stderr);
    return;
  }
  /* ----------------------- */

  /* Copy source IP and destination IP */
  packet->source_IP = ntohl (ip_header->source_address);
  packet->dest_IP = ntohl (ip_header->dest_address);
  /* --------------------------------- */

  raw += (int) ip_header_length;
  raw_length -= (int) ip_header_length;

  int transport_header_length;

  if (ip_header->protocol == TCP)
  {
    assert (sizeof (tcp_header_t) == MIN_TCP_HEADER_LENGTH);

    if (raw_length < MIN_TCP_HEADER_LENGTH)
    {
      fprintf (stderr, "Packet is shorter than min TCP header length\n"); fflush (stderr);
      return;
    }

    tcp_header = (tcp_header_t *) raw;

    packet->source_port = ntohs (tcp_header->source_port);

    packet->dest_port = ntohs (tcp_header->dest_port);

    packet->seq_number = ntohl (tcp_header->seq_number);

    packet->ack_number = ntohl (tcp_header->ack_number);

    packet->flags = (uint8_t) get_16_bits (ntohs (tcp_header->data_offset_and_flags), 11, 16);

    uint8_t data_offset = (uint8_t) get_16_bits (ntohs (tcp_header->data_offset_and_flags), 1, 4);

    transport_header_length = (int) data_offset * sizeof (uint32_t);
  }

  else
  {
    assert (sizeof (udp_header_t) == MIN_UDP_HEADER_LENGTH);

    if (raw_length < MIN_UDP_HEADER_LENGTH)
    {
      fprintf (stderr, "Packet is shorter than min UDP header length\n"); fflush (stderr);
      return;
    }

    udp_header = (udp_header_t *) raw;

    packet->source_port = ntohs (udp_header->source_port);

    packet->dest_port = ntohs (udp_header->dest_port);

    packet->seq_number = 0; packet->ack_number = 0; packet->flags = 0;

    transport_header_length = MIN_UDP_HEADER_LENGTH;
  }

  raw += transport_header_length;
  raw_length -= transport_header_length;

  packet->data_length = (size_t) raw_length;
  packet->data = malloc (packet->data_length);

  memmove (packet->data, raw, packet->data_length);

  packet->valid = true;
}

uint8_t get_8_bits (uint8_t number, int start, int finish)
{
  assert (start > 0 && finish > 0);
  assert (start < 9 && finish < 9);
  assert (start <= finish);

  uint8_t left = MAX_8;
  uint8_t right = MAX_8;

  left = (left >> (start - 1));
  right = (right << (8 - finish));

  number = (((number & left) & right) >> (8 - finish));

  return number;
}

uint16_t get_16_bits (uint16_t number, int start, int finish)
{
  assert (start > 0 && finish > 0);
  assert (start < 17 && finish < 17);
  assert (start <= finish);

  uint16_t left = MAX_16;
  uint16_t right = MAX_16;

  left = (left >> (start - 1));
  right = (right << (16 - finish));

  number = (((number & left) & right) >> (16 - finish));

  return number;
}
