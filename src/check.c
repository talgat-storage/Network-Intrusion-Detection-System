#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "subreg.h"
#include "needle.h"

#include "check.h"

bool check_ip (ip_t *, uint32_t);
bool check_port (port_t *, uint16_t);
bool check_option (option_t *, packet_t *);

rule_t *check_with_rules (packet_t *packet, rule_t *rules)
{
  rule_t *cur_rule;

  for (cur_rule = rules; cur_rule != NULL; cur_rule = cur_rule->next)
  {
    if (strcmp (cur_rule->protocol, STRING_HTTP) == 0 || strcmp (cur_rule->protocol, STRING_TCP) == 0)
    {
      if (strcmp (STRING_TCP, packet->transport_protocol) != 0)
      {
        fprintf (stderr, "Packet's transport protocol %s is not %s\n", packet->transport_protocol, STRING_TCP); fflush (stderr);
        continue;
      }
    }
    else
    {
      if (strcmp (cur_rule->protocol, packet->transport_protocol) != 0)
      {
        fprintf (stderr, "Packet's transport protocol %s is not %s\n", packet->transport_protocol, cur_rule->protocol); fflush (stderr);
        continue;
      }
    }

    bool matched;

    matched = check_ip (&(cur_rule->source_ip), packet->source_IP);
    if (matched == false)
    {
      fprintf (stderr, "Packet's source IP was not matched\n"); fflush (stderr);
      continue;
    }

    matched = check_port (&(cur_rule->source_port), packet->source_port);
    if (matched == false)
    {
      fprintf (stderr, "Packet's source port was not matched\n"); fflush (stderr);
      continue;
    }

    matched = check_ip (&(cur_rule->dest_ip), packet->dest_IP);
    if (matched == false)
    {
      fprintf (stderr, "Packet's destination IP was not matched\n"); fflush (stderr);
      continue;
    }

    matched = check_port (&(cur_rule->dest_port), packet->dest_port);
    if (matched == false)
    {
      fprintf (stderr, "Packet's destination port was not matched\n"); fflush (stderr);
      continue;
    }

    option_t *cur_option;
    for (cur_option = cur_rule->options; cur_option != NULL; cur_option = cur_option->next)
    {
      matched = check_option (cur_option, packet);
      if (matched == false)
      {
        fprintf (stderr, "Packet's option %s was not matched\n", cur_option->name); fflush (stderr);
        break;
      }
    }

    if (cur_option != NULL)
    {
      continue;
    }

    break;
  }

  return cur_rule;
}

bool check_ip (ip_t *rule_ip, uint32_t ip)
{
  return (ip >= rule_ip->start && ip <= rule_ip->finish) ? true : false;
}

bool check_port (port_t *rule_port, uint16_t port)
{
  if (rule_port->colon_found == true)
  {
    return (port >= rule_port->start && port <= rule_port->finish) ? true : false;
  }

  else
  {
    for (int i = 0; i < rule_port->number_of_ports; i++)
    {
      if (port == rule_port->ports[i])
      {
        return true;
      }
    }
  }

  return false;
}

uint8_t set_bit (uint8_t, int);

bool check_option (option_t *option, packet_t *packet)
{
  uint8_t value_8;
  uint16_t value_16;
  uint32_t value_32;

  if (strcmp (option->name, STRING_MSG) == 0)
  {
    return true;
  }

  if (strcmp (option->name, STRING_TOS) == 0)
  {
    value_8 = (uint8_t) atol (option->value);

    return packet->type_of_service == value_8 ? true : false;
  }

  if (strcmp (option->name, STRING_LEN) == 0)
  {
    value_8 = (uint8_t) atol (option->value);

    return packet->ip_header_length == value_8 ? true : false;
  }

  if (strcmp (option->name, STRING_OFF) == 0)
  {
    value_16 = (uint16_t) atol (option->value);

    return packet->frag_offset == value_16 ? true : false;
  }

  if (strcmp (option->name, STRING_SEQ) == 0)
  {
    value_32 = (uint32_t) atol (option->value);

    return packet->seq_number == value_32 ? true : false;
  }

  if (strcmp (option->name, STRING_ACK) == 0)
  {
    value_32 = (uint32_t) atol (option->value);

    return packet->ack_number == value_32 ? true : false;
  }

  if (strcmp (option->name, STRING_FLAGS) == 0)
  {
    value_8 = 0;

    if (strstr (option->value, "F") != NULL)
    {
      value_8 = set_bit (value_8, 8);
    }
    if (strstr (option->value, "S") != NULL)
    {
      value_8 = set_bit (value_8, 7);
    }
    if (strstr (option->value, "R") != NULL)
    {
      value_8 = set_bit (value_8, 6);
    }
    if (strstr (option->value, "P") != NULL)
    {
      value_8 = set_bit (value_8, 5);
    }
    if (strstr (option->value, "A") != NULL)
    {
      value_8 = set_bit (value_8, 4);
    }

    return (value_8 & packet->flags) == value_8 ? true : false;
  }

  if (strcmp (option->name, STRING_HTTP_REQ) == 0)
  {
    if (strcmp (option->value, "GET")   != 0 &&
        strcmp (option->value, "PUT")   != 0 &&
        strcmp (option->value, "POST")  != 0 &&
        strcmp (option->value, "HEAD")  != 0 &&
        strcmp (option->value, "URI")   != 0)
    {
      return false;
    }

    char regex[LINE_LENGTH];

    if (strcmp (option->value, "URI") == 0)
    {
      sprintf (regex, "\\s*\\S+\\s+\\S+\\s+HTTP/.*");
    }
    else
    {
      sprintf (regex, "\\s*\\%s\\s+\\S+\\s+HTTP/.*", option->value);
    }

    subreg_capture_t captures[MAX_NUM_CAPTURES];

    int number_of_captures = subreg_match (regex, packet->data, captures, MAX_NUM_CAPTURES, MAX_DEPTH);

    return number_of_captures > 0 ? true : false;
  }

  if (strcmp (option->name, STRING_CONTENT) == 0)
  {
    return find_needle (packet->data, packet->data_length,
                        (void *) option->value, strlen (option->value)) == NULL ? false : true;
  }

  return false;
}

uint8_t set_bit (uint8_t number, int bit)
{
  assert (bit > 0 && bit < 9);

  uint8_t one_bit = 128;

  one_bit = (one_bit >> (bit - 1));

  number = (number | one_bit);

  return number;
}


