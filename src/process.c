#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "packet.h"
#include "check.h"
#include "output.h"

#include "process.h"

void process_packet (u_char *arg, const struct pcap_pkthdr *pkthdr,
                     const u_char *raw)
{
  rule_t *rules = *((rule_t **) arg);

  int data_link_offset = *((int *) ((void *) arg + sizeof (rule_t *)));

  packet_t packet;

  parse_packet (&packet, data_link_offset, (void *) raw, (int) pkthdr->caplen);

  if (packet.valid == true)
  {
    rule_t *match_rule = check_with_rules (&packet, rules);

    if (match_rule != NULL)
    {
      print_output (match_rule, &packet);
    }

    else
    {
      print_packet (&packet);
    }

    free (packet.data);
  }
}
