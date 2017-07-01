#ifndef STRUCTURES_H
#define STRUCTURES_H

#include "libraries.h"
#include "definitions.h"

typedef struct ip_tag
{
  char *str;

  uint32_t start;
  uint32_t finish;
}
ip_t;

typedef struct port_tag
{
  char *str;

  bool colon_found;
  uint16_t start;
  uint16_t finish;

  int number_of_ports;
  uint16_t *ports;
}
port_t;

struct option_tag;

typedef struct rule_tag
{
  char *str;

  char *protocol;

  struct ip_tag source_ip;
  struct ip_tag dest_ip;

  struct port_tag source_port;
  struct port_tag dest_port;

  struct option_tag *options;

  struct rule_tag *prev;
  struct rule_tag *next;
}
rule_t;

typedef struct option_tag {
  char *name;
  char *value;
  struct option_tag *next;
}
option_t;

typedef struct packet_tag
{
  bool valid;

  /* Network layer */
  uint8_t version; /* 4 bits */
  uint8_t ip_header_length; /* 4 bits */
  uint8_t type_of_service;

  uint16_t frag_offset; /* 13 bits */

  char transport_protocol[STRING_LENGTH];

  uint32_t source_IP;
  uint32_t dest_IP;

  /* Transport layer */
  uint16_t source_port;
  uint16_t dest_port;

  uint32_t seq_number; /* only TCP */
  uint32_t ack_number; /* only TCP */

  uint8_t flags; /* 6 bits */ /* only TCP */

  /* Application layer */
  void *data;
  size_t data_length;
}
packet_t;

/* IP header structure */
typedef struct ip_header_tag
{
  uint8_t version_and_ihl; /* 4 bits each */ /* copy */
  uint8_t type_of_service; /* copy */
  uint16_t total_length;

  uint16_t identification;
  uint16_t flags_and_frag_os; /* 3 bits and 13 bits */ /* copy */

  uint8_t time_to_live;
  uint8_t protocol; /* copy */
  uint16_t header_checksum;

  uint32_t source_address; /* copy */

  uint32_t dest_address; /* copy */
}
ip_header_t;

/* TCP header structure */
typedef struct tcp_header_tag
{
  uint16_t source_port; /* copy */
  uint16_t dest_port; /* copy */

  uint32_t seq_number; /* copy */

  uint32_t ack_number; /* copy */

  uint16_t data_offset_and_flags; /* 4 bits and 6 bits */
  uint16_t window;

  uint16_t checksum;
  uint16_t urgent_pointer;
}
tcp_header_t;

/* UDP header structure */
typedef struct udp_header_tag
{
  uint16_t source_port; /* copy */
  uint16_t dest_port; /* copy */

  uint16_t length;
  uint16_t checksum;
}
udp_header_t;

#endif
