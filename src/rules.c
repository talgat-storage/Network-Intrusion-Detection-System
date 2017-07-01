#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "subreg.h"

#include "rules.h"

#define MAX_32 (0xFFFFFFFF)
#define MAX_16 (0xFFFF)

enum {WHOLE = 0, PROTOCOL, SOURCE_IP, SOURCE_PORT, DEST_IP, DEST_PORT};

void set_ranges (rule_t *);

rule_t *get_rules (char *filename)
{
  rule_t *rules = NULL;

  char regex[LINE_LENGTH];
  char line[LINE_LENGTH];

  subreg_capture_t captures[MAX_NUM_CAPTURES];

  strcpy (regex, "\\s*alert\\s+((?tcp)|(?udp)|(?http))\\s+"
                 "((?any)|(?(?\\d|\\.|/)+))\\s+((?any)|(?(?\\d|:|,)+))\\s*"
                 "->\\s*"
                 "((?any)|(?(?\\d|\\.|/)+))\\s+((?any)|(?(?\\d|:|,)+))\\s*"
                 "(?\\("
                 "(?\\s*((?\\w)+)\\s*:\\s*(?(?\\q((?\\Q)*)\\q)|((?\\w)+))\\s*;?\\s*)*"
                 "\\))?\\s*");

  FILE *file = fopen (filename, "r");
  if (file == NULL)
  {
    fprintf (stderr, "Could not open %s\n", filename);
    exit (EXIT_FAILURE);
  }

  while (fgets (line, LINE_LENGTH, file))
  {
    if (strlen (line) < 4)
    {
      continue;
    }

    int number_of_captures = subreg_match (regex, line, captures, MAX_NUM_CAPTURES, MAX_DEPTH);
    if (number_of_captures < 6)
    {
      continue;
    }

    rule_t *new_rule = (rule_t *) malloc (sizeof (rule_t));

    new_rule->str = strndup (captures[WHOLE].start, captures[WHOLE].length);

    new_rule->protocol = strndup (captures[PROTOCOL].start, captures[PROTOCOL].length);

    new_rule->source_ip.str = strndup (captures[SOURCE_IP].start, captures[SOURCE_IP].length);

    new_rule->source_port.str = strndup (captures[SOURCE_PORT].start, captures[SOURCE_PORT].length);

    new_rule->dest_ip.str = strndup (captures[DEST_IP].start, captures[DEST_IP].length);

    new_rule->dest_port.str = strndup (captures[DEST_PORT].start, captures[DEST_PORT].length);

    new_rule->options = NULL;

    for (int i = DEST_PORT + 1; i < number_of_captures; i += 2)
    {
      option_t *new_option = (option_t *) malloc (sizeof (option_t));

      new_option->name = strndup (captures[i].start, captures[i].length);

      new_option->value = strndup (captures[i+1].start, captures[i+1].length);

      new_option->next = new_rule->options;

      new_rule->options = new_option;
    }

    set_ranges (new_rule);

    new_rule->prev = NULL;
    new_rule->next = rules;

    if (rules != NULL)
    {
      rules->prev = new_rule;
    }

    rules = new_rule;
  }

  fclose (file);

  return rules;
}

void set_ip_range (ip_t *);
void set_port_values (port_t *);

void set_ranges (rule_t *rule)
{
  set_ip_range (&(rule->source_ip));

  set_ip_range (&(rule->dest_ip));

  set_port_values (&(rule->source_port));

  set_port_values (&(rule->dest_port));
}

uint32_t zero_right_part (uint32_t, int);
uint32_t one_right_part (uint32_t, int);

void set_ip_range (ip_t *ip)
{
  if (strcmp (ip->str, ANY) == 0)
  {
    ip->start = 0;
    ip->finish = MAX_32;
    return;
  }

  char *slash = strstr (ip->str, "/");
  bool slash_found = slash == NULL ? false : true;
  if (slash_found == true)
  {
    *slash = '\0';
  }

  struct in_addr address;
  int rv = inet_pton (AF_INET, ip->str, (void *) &address);
  if (rv != 1)
  {
    fprintf (stderr, "Could not convert IP address: %s\n", ip->str);
    exit (EXIT_FAILURE);
  }

  uint32_t ip_number = ntohl ((uint32_t) address.s_addr);

  if (slash_found == true)
  {
    int mask = (int) atol (slash + 1);
    if (mask < 0 || mask > 32)
    {
      fprintf (stderr, "Subnet mask is invalid\n");
      exit (EXIT_FAILURE);
    }

    if (mask == 0)
    {
      ip->start = 0;
      ip->finish = MAX_32;
    }
    else if (mask == 32)
    {
      ip->start = ip_number;
      ip->finish = ip_number;
    }
    else
    {
      ip->start = zero_right_part (ip_number, mask);
      ip->finish = one_right_part (ip_number, mask);
    }

    *slash = '/';
  }

  else
  {
    ip->start = ip_number;
    ip->finish = ip_number;
  }
}

uint32_t zero_right_part (uint32_t ip, int mask)
{
  uint32_t number = MAX_32;

  number = ~(number >> mask);

  number = (ip & number);

  return number;
}

uint32_t one_right_part (uint32_t ip, int mask)
{
  uint32_t number = MAX_32;

  number = (number >> mask);

  number = (ip | number);

  return number;
}

void set_port_values (port_t *port)
{
  if (strcmp (port->str, ANY) == 0)
  {
    port->colon_found = true;
    port->start = 0;
    port->finish = MAX_16;
    return;
  }

  char *colon = strstr (port->str, ":");
  char *comma = strstr (port->str, ",");

  if (colon != NULL && comma != NULL)
  {
    fprintf (stderr, "Invalid ports: colon and comma in %s\n", port->str);
    exit (EXIT_FAILURE);
  }

  port->colon_found = colon == NULL ? false : true;

  if (port->colon_found == true)
  {
    if (port->str == colon)
    {
      port->start = 0;
    }
    else
    {
      *colon = '\0';
      port->start = (uint16_t) atol (port->str);
      *colon = ':';
    }

    if (port->str + strlen (port->str) - 1 == colon)
    {
      port->finish = MAX_16;
    }
    else
    {
      port->finish = (uint16_t) atol (colon + 1);
    }
  }

  else
  {
    char regex[LINE_LENGTH];
    subreg_capture_t captures[MAX_NUM_CAPTURES];

    strcpy (regex, "(?((?\\d)+),?)+");

    int number_of_captures = subreg_match (regex, port->str, captures, MAX_NUM_CAPTURES, MAX_DEPTH);
    if (number_of_captures < 2)
    {
      fprintf (stderr, "Invalid ports: no matching\n");
      exit (EXIT_FAILURE);
    }

    port->number_of_ports = number_of_captures - 1;

    port->ports = (uint16_t *) malloc (port->number_of_ports * sizeof (uint16_t));

    for (int i = 1; i < port->number_of_ports; i++)
    {
      comma = ((char *) (captures[i].start)) + captures[i].length;

      *comma = '\0';

      port->ports[i - 1] = (uint16_t) atol (captures[i].start);

      *comma = ',';
    }

    port->ports[port->number_of_ports - 1] = (uint16_t) atol (captures[port->number_of_ports].start);
  }
}
