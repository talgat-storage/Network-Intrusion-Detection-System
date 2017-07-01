#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "needle.h"

#include "output.h"

#define RED "\x1B[31m"
#define RESET "\x1B[0m"

void print_one_rule (rule_t *);

void print_ip (ip_t *);
void print_port (port_t *);

option_t *which_option (rule_t *, char *);
void convert_ip_to_string (char *, uint32_t);
void print_flags (option_t *);
void print_payload (option_t *, packet_t *);

void print_packet_flags (uint8_t);

void print_rules (rule_t *rules)
{
  rule_t *cur_rule;

  if (rules == NULL)
  {
    return;
  }

  for (cur_rule = rules; cur_rule->next != NULL; cur_rule = cur_rule->next);

  int count = 0;

  for (; cur_rule != NULL; cur_rule = cur_rule->prev)
  {
    count++;

    printf ("Rule #%d\n", count);

    print_one_rule (cur_rule);

    printf ("\n\n");
  }
}

void print_one_rule (rule_t *rule)
{
  printf ("  |-Protocol: %s\n", rule->protocol);

  printf ("  |-Source IP: "); print_ip (&(rule->source_ip));

  printf ("  |-Source port: "); print_port (&(rule->source_port));

  printf ("  |-Destination IP: "); print_ip (&(rule->dest_ip));

  printf ("  |-Destination port: "); print_port (&(rule->dest_port));

  if (rule->options != NULL)
  {
    printf ("  |-Options:\n");
  }

  for (option_t* cur_option = rule->options; cur_option != NULL; cur_option = cur_option->next)
  {
    printf ("    |-%s: %s\n", cur_option->name, cur_option->value);
  }
}

void print_ip (ip_t *ip)
{
  struct in_addr address;

  char ip_start[STRING_LENGTH];
  char ip_finish[STRING_LENGTH];

  address.s_addr = (in_addr_t) htonl (ip->start);

  char *rv = (char *) inet_ntop (AF_INET, (void *) &address, ip_start, STRING_LENGTH);
  if (rv == NULL)
  {
    fprintf (stderr, "Could not convert IP address\n");
    exit (EXIT_FAILURE);
  }

  address.s_addr = (in_addr_t) htonl (ip->finish);

  rv = (char *) inet_ntop (AF_INET, (void *) &address, ip_finish, STRING_LENGTH);
  if (rv == NULL)
  {
    fprintf (stderr, "Could not convert IP address\n");
    exit (EXIT_FAILURE);
  }

  printf ("%s -> start: %s, end: %s\n", ip->str, ip_start, ip_finish);
}

void print_port (port_t *port)
{
  printf ("%s ->", port->str);

  if (port->colon_found == true)
  {
    printf (" start: %d, end: %d\n", (int) port->start, (int) port->finish);
  }

  else
  {
    for (int i = 0; i < port->number_of_ports; i++)
    {
      printf (" %d", (int) port->ports[i]);
    }

    printf ("\n");
  }
}

void print_output (rule_t *rule, packet_t *packet)
{
  printf ("Rule: "); fflush (stdout);

  printf ("%s", rule->str); fflush (stdout);

  if (rule->str[strlen (rule->str) - 1] != '\n')
  {
    printf ("\n");
  }

  printf ("=====================\n"); fflush (stdout);

  option_t *option_specified;

  printf ("[IP header]\n");
  printf ("Version: %d\n", (int) packet->version);

  option_specified = which_option (rule, STRING_LEN);
  if (option_specified != NULL)
  {
    printf (RED);
  }
  printf ("Header Length: %d bytes\n", (int) packet->ip_header_length); printf (RESET);

  option_specified = which_option (rule, STRING_TOS);
  if (option_specified != NULL)
  {
    printf (RED);
  }
  printf ("ToS: %x\n", (int) packet->type_of_service); printf (RESET);

  option_specified = which_option (rule, STRING_OFF);
  if (option_specified != NULL)
  {
    printf (RED);
  }
  printf ("Fragment Offset: %d\n", (int) packet->frag_offset); printf (RESET);

  char ip[STRING_LENGTH];

  if (strcmp (rule->source_ip.str, ANY) != 0)
  {
    printf (RED);
  }
  convert_ip_to_string (ip ,packet->source_IP);
  printf ("Source: %s\n", ip); printf (RESET);

  if (strcmp (rule->dest_ip.str, ANY) != 0)
  {
    printf (RED);
  }
  convert_ip_to_string (ip, packet->dest_IP);
  printf ("Destination: %s\n", ip); printf (RESET);

  printf ("\n");

  if (strcmp (packet->transport_protocol, STRING_TCP) == 0)
  {
    printf ("[TCP header]\n");
  }
  else
  {
    printf ("[UDP header]\n");
  }

  if (strcmp (rule->source_port.str, ANY) != 0)
  {
    printf (RED);
  }
  printf ("Source port: %d\n", packet->source_port); printf (RESET);

  if (strcmp (rule->dest_port.str, ANY) != 0)
  {
    printf (RED);
  }
  printf ("Destination port: %d\n", packet->dest_port); printf (RESET);

  if (strcmp (packet->transport_protocol, STRING_TCP) == 0)
  {
    option_specified = which_option (rule, STRING_SEQ);
    if (option_specified != NULL)
    {
      printf (RED);
    }
    printf ("Sequence Number: %d\n", (int) packet->seq_number); printf (RESET);

    option_specified = which_option (rule, STRING_ACK);
    if (option_specified != NULL)
    {
      printf (RED);
    }
    printf ("Acknowledgement Number: %d\n", (int) packet->ack_number); printf (RESET);

    option_specified = which_option (rule, STRING_FLAGS);
    if (option_specified != NULL)
    {
      printf (RED);
    }

    printf ("Flags:"); print_flags (option_specified); printf (RESET); printf ("\n");
  }

  printf ("\n");

  if (strcmp (packet->transport_protocol, STRING_TCP) == 0)
  {
    printf ("[TCP payload]\n");
  }
  else
  {
    printf ("[UDP payload]\n");
  }

  option_specified = which_option (rule, STRING_HTTP_REQ);
  if (option_specified != NULL)
  {
    printf (RED);
    printf ("HTTP Request: %s\n", option_specified->value); printf (RESET);
  }

  option_specified = which_option (rule, STRING_CONTENT);
  if (option_specified != NULL)
  {
    printf (RED);
  }

  printf ("Payload: "); printf (RESET);
  print_payload (option_specified, packet);
  printf ("\n");

  printf ("=====================\n"); fflush (stdout);
  option_specified = which_option (rule, STRING_MSG);
  if (option_specified != NULL)
  {
    printf ("Message: %s\n", option_specified->value);
  }

  printf ("\n");
}

option_t *which_option (rule_t *rule, char *option_name)
{
  option_t *cur_option;

  for (cur_option = rule->options; cur_option != NULL; cur_option = cur_option->next)
  {
    if (strcmp (cur_option->name, option_name) == 0)
    {
      break;
    }
  }

  return cur_option;
}

void convert_ip_to_string (char *ip_str, uint32_t ip)
{
  struct in_addr address;

  address.s_addr = (in_addr_t) htonl (ip);

  char *rv = (char *) inet_ntop (AF_INET, (void *) &address, ip_str, STRING_LENGTH);
  if (rv == NULL)
  {
    fprintf (stderr, "Could not convert IP address\n");
    exit (EXIT_FAILURE);
  }
}

void print_flags (option_t *option)
{
  if (option == NULL)
  {
    return;
  }

  if (strstr (option->value, "F") != NULL)
  {
    printf (" FIN");
  }
  if (strstr (option->value, "S") != NULL)
  {
    printf (" SYN");
  }
  if (strstr (option->value, "R") != NULL)
  {
    printf (" RST");
  }
  if (strstr (option->value, "P") != NULL)
  {
    printf (" PSH");
  }
  if (strstr (option->value, "A") != NULL)
  {
    printf (" ACK");
  }
}

void print_payload (option_t *option, packet_t *packet)
{
  if (option == NULL)
  {
    for (int i = 0; i < packet->data_length; i++)
    {
      if (isprint (((char *) packet->data)[i]))
      {
        printf ("%c", ((char *) packet->data)[i]);
      }
      else
      {
        printf (".");
      }
    }

    return;
  }

  char *needle = find_needle (packet->data, packet->data_length,
                              (void *) option->value, strlen (option->value));

  int before = needle - (char *) packet->data;

  int after = packet->data_length - before - strlen (option->value);

  for (int i = 0; i < before; i++)
  {
    if (isprint (((char *) packet->data)[i]))
    {
      printf ("%c", ((char *) packet->data)[i]);
    }
    else
    {
      printf (".");
    }
  }

  printf (RED); printf ("%s", option->value); printf (RESET);

  for (int i = before + strlen (option->value);
       i < before + strlen (option->value) + after;
       i++)
  {
    if (isprint (((char *) packet->data)[i]))
    {
      printf ("%c", ((char *) packet->data)[i]);
    }
    else
    {
      printf (".");
    }
  }
}

void print_packet (packet_t *packet)
{
  char source_ip[STRING_LENGTH];
  char dest_ip[STRING_LENGTH];

  convert_ip_to_string (source_ip, packet->source_IP);
  convert_ip_to_string (dest_ip, packet->dest_IP);

  printf ("Newly captured packet\n");
  printf ("\t|-");
  printf ("--Network Layer---\n");
  printf ("\t|-");
  printf ("IP version is %d\n", (int) packet->version);
  printf ("\t|-");
  printf ("IP header length is %d\n", (int) packet->ip_header_length);
  printf ("\t|-");
  printf ("Type of service is %d\n", (int) packet->type_of_service);
  printf ("\t|-");
  printf ("Fragmentation offset is %d\n", (int) packet->frag_offset);
  printf ("\t|-");
  printf ("Protocol is %s\n", packet->transport_protocol);
  printf ("\t|-");
  printf ("Source IP is %s\n", source_ip);
  printf ("\t|-");
  printf ("Destination IP is %s\n", dest_ip);
  printf ("\t|\n");
  printf ("\t|-");
  printf ("--Transport layer---\n");
  printf ("\t|-");
  printf ("Source port is %d\n", (int) packet->source_port);
  printf ("\t|-");
  printf ("Destination port is %d\n", (int) packet->dest_port);
  printf ("\t|-");
  printf ("Sequence number is %lu\n", (long unsigned) packet->seq_number);
  printf ("\t|-");
  printf ("ACK number is %lu\n", (long unsigned) packet->ack_number);
  printf ("\t|-");
  printf ("Flags:"); print_packet_flags (packet->flags); printf ("\n");
  printf ("\t|\n");
  printf ("\t|-");
  printf ("--Application layer---\n");
  printf ("\t|-");
  printf ("Payload: ");
  for (int i = 0; i < (int) packet->data_length; i++)
  {
    if (isprint (((char *) packet->data)[i]))
    {
      printf ("%c", ((char *) packet->data)[i]);
    }
    else
    {
      printf (".");
    }
  }

  printf ("\n\n");
}

bool is_bit_set (uint8_t, int);

void print_packet_flags (uint8_t flags)
{
  if (is_bit_set (flags, 8))
  {
    printf (" FIN");
  }

  if (is_bit_set (flags, 7))
  {
    printf (" SYN");
  }

  if (is_bit_set (flags, 6))
  {
    printf (" RST");
  }

  if (is_bit_set (flags, 5))
  {
    printf (" PSH");
  }

  if (is_bit_set (flags, 4))
  {
    printf (" ACK");
  }
}

bool is_bit_set (uint8_t number, int bit)
{
  assert (bit > 0 && bit < 9);

  uint8_t one_bit = 128;

  one_bit = (one_bit >> (bit - 1));

  number = (number & one_bit);

  return number == one_bit;
}
