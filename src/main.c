#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "rules.h"
#include "output.h"
#include "capture.h"
#include "process.h"

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "Please, provide a rules file\n");
    exit (EXIT_FAILURE);
  }

  rule_t *rules = get_rules (argv[1]);
  print_rules (rules);

  pcap_t *handle = pcap_init ();

  int data_link_offset = pcap_datalink_offset (handle);

  void *arg = malloc (sizeof (rule_t *) + sizeof (int));

  *((rule_t **) arg) = rules;

  *((int *) (arg + sizeof (rule_t *))) = data_link_offset;

  pcap_loop (handle, -1, process_packet, (u_char *) arg);

  return 0;
}
