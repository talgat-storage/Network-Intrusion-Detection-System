#include "libraries.h"
#include "definitions.h"
#include "structures.h"

#include "capture.h"

#define BYTES_TO_CAPTURE (0xffff)

enum {MINUS_ONE = -1, ZERO = 0, ONE = 1};

pcap_t *pcap_init (void)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int rv;

  char *device_name = pcap_lookupdev (errbuf);
  if (device_name == NULL)
  {
    fprintf (stderr, "Look-up device: %s\n", errbuf);
    exit (EXIT_FAILURE);
  }

  printf ("Device name: %s\n\n", device_name);

  pcap_t *handle = pcap_create (device_name, errbuf);
  if (handle == NULL)
  {
    fprintf (stderr, "Create: %s\n", errbuf);
    exit (EXIT_FAILURE);
  }

  rv = pcap_set_snaplen (handle, BYTES_TO_CAPTURE);
  if (rv != ZERO)
  {
    fprintf (stderr, "Set snapshot length: %s\n", pcap_statustostr (rv));
    exit (EXIT_FAILURE);
  }

  rv = pcap_set_promisc (handle, ONE);
  if (rv != ZERO)
  {
    fprintf (stderr, "Set promiscuous mode: %s\n", pcap_statustostr (rv));
    exit (EXIT_FAILURE);
  }

  rv = pcap_set_immediate_mode (handle, ONE);
  if (rv != ZERO)
  {
    fprintf (stderr, "Set immediate mode: %s\n", pcap_statustostr (rv));
    exit (EXIT_FAILURE);
  }

  rv = pcap_activate (handle);
  if (rv != ZERO)
  {
    fprintf (stderr, "Activate: %s\n", pcap_statustostr (rv));
    exit (EXIT_FAILURE);
  }

  return handle;
}

int pcap_datalink_offset (pcap_t *handle)
{
  int offset = -1;

  switch (pcap_datalink (handle))
  {
  case DLT_EN10MB:
    offset = 14;
    break;

  case DLT_IEEE802:
    offset = 22;
    break;

  case DLT_FDDI:
    offset = 21;
    break;

  case DLT_NULL:
    offset = 4;
    break;

  default:
    break;
  }

  if (offset == -1)
  {
    fprintf (stderr, "Data link %s is not supported\n", pcap_datalink_val_to_name (pcap_datalink (handle)));
    exit (EXIT_FAILURE);
  }

  return offset;
}
