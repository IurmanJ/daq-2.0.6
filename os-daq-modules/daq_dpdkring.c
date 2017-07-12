#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ring.h>
#include <rte_prefetch.h>

#define DAQ_DPDK_VERSION 2
#define MAX_ARGS 64

#define BURST_SIZE 32

typedef struct _dpdk_instance
{
	struct _dpdk_instance *next;
	#define DPDKINST_STARTED	0x1
	uint32_t flags;
	int ingress_index;
	int egress_index;
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring_peer;
	struct rte_ring *tx_ring_reverse;
	struct rte_mempool *mbuf_pool;
	int tx_peer_start;
	int tx_peer_end;
	struct rte_mbuf *tx_peer_burst[BURST_SIZE];
} DpdkInstance;

typedef struct _dpdk_context
{
	char *device;
	char *filter;
	int snaplen;
	int timeout;
	int debug;
	DpdkInstance *instances;
	int peer_mode;
	int intf_count;
	struct sfbpf_program fcode;
	volatile int break_loop;
	int promisc_flag;
	DAQ_Stats_t stats;
	DAQ_State state;
	char errbuf[256];
} Dpdk_Context_t;

static void dpdkring_daq_reset_stats(void *handle);

static int start_instance(Dpdk_Context_t *dpdkc, DpdkInstance *instance)
{
	char rx_name[20], tx_peer_name[20], tx_reverse_name[20];
	
	/* No matter which mode is selected, we must find an RX ring */
	snprintf(rx_name, sizeof(rx_name), "dpdk%d_2_snort", instance->ingress_index);
	instance->rx_ring = rte_ring_lookup(rx_name);
	
	if (instance->rx_ring == NULL)
	{
		DPE(dpdkc->errbuf, "%s: Cannot get RX ring (%s)\n", __FUNCTION__, rx_name);
		return DAQ_ERROR;
	}
	
	if (!dpdkc->peer_mode)
	{
		/* PASSIVE mode (there is no TX rings) */
		instance->tx_ring_peer = NULL;
		instance->tx_ring_reverse = NULL;
	}
	else
	{
		/* Not PASSIVE mode (must find 2 TX rings) */
		snprintf(tx_peer_name, sizeof(tx_peer_name), "snort_2_dpdk%d", instance->egress_index);
		snprintf(tx_reverse_name, sizeof(tx_reverse_name), "snort_2_dpdk%d", instance->ingress_index);
		
		instance->tx_ring_peer = rte_ring_lookup(tx_peer_name);
		instance->tx_ring_reverse = rte_ring_lookup(tx_reverse_name);
		
		if (instance->tx_ring_peer == NULL || instance->tx_ring_reverse == NULL)
		{
			DPE(dpdkc->errbuf, "%s: (Peer mode) Cannot get both TX peer ring (%s) and TX reverse ring (%s)\n", __FUNCTION__, tx_peer_name, tx_reverse_name);
			return DAQ_ERROR;
		}
	}

	instance->flags |= DPDKINST_STARTED;
	return DAQ_SUCCESS;
}

static void destroy_instance(DpdkInstance *instance)
{
	int i;
	if (instance)
	{
		if (instance->flags & DPDKINST_STARTED)
		{
			for (i = instance->tx_peer_start; i < instance->tx_peer_end; i++)
				rte_pktmbuf_free(instance->tx_peer_burst[i]);
				
			instance->flags &= ~DPDKINST_STARTED;
		}

		free(instance);
	}
}

static DpdkInstance *create_instance(const char *device, const char *peer, DpdkInstance *parent, char *errbuf, size_t errlen)
{
	DpdkInstance *instance;
	int ingress_index, egress_index;
	char poolname[64];
	
	instance = calloc(1, sizeof(DpdkInstance));
	if (!instance)
	{
		snprintf(errbuf, errlen, "%s: Cannot allocate a new instance structure.", __FUNCTION__);
		goto err;
	}
	
	if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &ingress_index) != 1)
	{
		snprintf(errbuf, errlen, "%s: Invalid interface syntax: \"%s\"", __FUNCTION__, device);
		goto err;
	}
	
	instance->ingress_index = ingress_index;
	
	if (peer == NULL)
	{
		// PASSIVE mode: single instance (eg. "dpdk0")
		instance->egress_index = -1;
	}
	else
	{
		// PEER mode: double instance (eg. "dpdk0:dpdk1")
		if (strncmp(peer, "dpdk", 4) != 0 || sscanf(&peer[4], "%d", &egress_index) != 1)
		{
			snprintf(errbuf, errlen, "%s: Invalid interface syntax: \"%s\"", __FUNCTION__, peer);
			goto err;
		}
		
		instance->egress_index = egress_index;
	}

	// TODO: find a common way between the origin (for this example it's fastclick) and here to have the same pool names (pass it as an argument ?)
	snprintf(poolname, sizeof(poolname), "click_mempool_snort_%d", instance->ingress_index);
	instance->mbuf_pool = rte_mempool_lookup(poolname);

	if (instance->mbuf_pool == NULL)
	{
		snprintf(errbuf, errlen, "%s: Cannot find mbuf_pool %s\n", __FUNCTION__, poolname);
		goto err;
	}
	
	instance->tx_peer_start = 0;
	instance->tx_peer_end = 0;
	
	return instance;

err:
	destroy_instance(instance);
	return NULL;
}

static int dpdk_close(Dpdk_Context_t *dpdkc)
{
	DpdkInstance *instance;

	if (!dpdkc)
		return -1;

	while((instance = dpdkc->instances) != NULL)
	{
		dpdkc->instances = instance->next;
		destroy_instance(instance);
	}

	sfbpf_freecode(&dpdkc->fcode);
	dpdkc->state = DAQ_STATE_STOPPED;
	
	return 0;
}

static int parse_args(char *inputstring, char **argv)
{
	char **ap;

	for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL; )
	{
		if (**ap != '\0' && ++ap >= &argv[MAX_ARGS])
			break;
	}

	return ap - argv;
}

static int dpdkring_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
	Dpdk_Context_t *dpdkc;
	DpdkInstance *instance;
	DAQ_Dict *entry;
	char intf[IFNAMSIZ], intf_peer[IFNAMSIZ];
	int num_intfs = 0;
	size_t len;
	char *dev;
	int ret, rval = DAQ_ERROR;
	char *dpdk_args = NULL;
	char argv0[] = "fake";
	char *argv[MAX_ARGS + 1];
	int argc;
	int called_instance_creation;

	dpdkc = calloc(1, sizeof(Dpdk_Context_t));
	if (!dpdkc)
	{
		snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	dpdkc->device = strdup(config->name);
	if (!dpdkc->device)
	{
		snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string (%s)!", __FUNCTION__, config->name);
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	dpdkc->snaplen = config->snaplen;
	dpdkc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
	dpdkc->promisc_flag = (config->flags & DAQ_CFG_PROMISC);

	/* Import the DPDK arguments */
	for (entry = config->values; entry; entry = entry->next)
	{
		if (!strcmp(entry->key, "dpdk_args"))
			dpdk_args = entry->value;
	}

	if (!dpdk_args)
	{
		snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
		rval = DAQ_ERROR_INVAL;
		goto err;
	}

	argv[0] = argv0;
	argc = parse_args(dpdk_args, &argv[1]) + 1;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
		rval = DAQ_ERROR_INVAL;
		goto err;
	}

	dpdkc->peer_mode = (config->mode == DAQ_MODE_PASSIVE) ? 0 : 1;
	
	dev = dpdkc->device;
	if ((len = strlen(dev)) <= 0 || *dev == ':' || (len > 0 && *(dev + len - 1) == ':') || (!dpdkc->peer_mode && strstr(dev, "::")))
	{
		snprintf(errbuf, errlen, "%s: Invalid interface specification: \"%s\"", __FUNCTION__, dpdkc->device);
		goto err;
	}

	while (*dev != '\0')
	{
		len = strcspn(dev, ":");
		if (len >= sizeof(intf))
		{
			snprintf(errbuf, errlen, "%s: Interface name too long (%zu)", __FUNCTION__, len);
			goto err;
		}
		
		if (len == 0)
		{
			if (*(dev+1) == ':')
			{
				if (num_intfs % 2 != 0)
				{
					snprintf(errbuf, errlen, "%s: Peer separator \"::\" must only be found between two pairs", __FUNCTION__);
					goto err;
				}
				len += 2;
			}
			else
			{
				if (dpdkc->peer_mode && (num_intfs % 2) == 0)
				{
					snprintf(errbuf, errlen, "%s: Peers must be separed by peer separator \"::\"", __FUNCTION__);
					goto err;
				}
				len++;
			}
		}
		else
		{
			num_intfs++;
			
			instance = NULL;
			called_instance_creation = 0;
			
			if (dpdkc->peer_mode)
			{
				if (num_intfs % 2 != 0)
					snprintf(intf, len+1, "%s", dev);
				else
				{
					snprintf(intf_peer, len+1, "%s", dev);
					instance = create_instance(intf, intf_peer, dpdkc->instances, errbuf, errlen);
					called_instance_creation = 1;
				}
			}
			else
			{
				snprintf(intf, len+1, "%s", dev);
				instance = create_instance(intf, NULL, dpdkc->instances, errbuf, errlen);
				called_instance_creation = 1;
			}
			
			if (called_instance_creation)
			{
				if (!instance)
					goto err;

				instance->next = dpdkc->instances;
				dpdkc->instances = instance;
				
				dpdkc->intf_count++;
			}
		}
		
		dev += len;
	}

	/* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
	if (!dpdkc->instances || (dpdkc->peer_mode && (num_intfs % 2) != 0))
	{
		snprintf(errbuf, errlen, "%s: Invalid interface specification: \"%s\"", __FUNCTION__, dpdkc->device, num_intfs);
		goto err;
	}
	
	/* Initialize other default configuration values. */
	dpdkc->debug = 0;

	/* Import the configuration dictionary requests. */
	for (entry = config->values; entry; entry = entry->next)
	{
		if (!strcmp(entry->key, "debug"))
			dpdkc->debug = 1;
	}

	dpdkc->state = DAQ_STATE_INITIALIZED;
	*ctxt_ptr = dpdkc;
	
	return DAQ_SUCCESS;

err:
	if (dpdkc)
	{
		dpdk_close(dpdkc);
		if (dpdkc->device)
			free(dpdkc->device);
		free(dpdkc);
	}
	return rval;
}

static int dpdkring_daq_set_filter(void *handle, const char *filter)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	struct sfbpf_program fcode;

	if (dpdkc->filter)
		free(dpdkc->filter);

	dpdkc->filter = strdup(filter);
	if (!dpdkc->filter)
	{
		DPE(dpdkc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
		return DAQ_ERROR;
	}

	if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->filter, 1, 0) < 0)
	{
		DPE(dpdkc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
		return DAQ_ERROR;
	}

	sfbpf_freecode(&dpdkc->fcode);

	dpdkc->fcode.bf_len = fcode.bf_len;
	dpdkc->fcode.bf_insns = fcode.bf_insns;

	return DAQ_SUCCESS;
}

static int dpdkring_daq_start(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	DpdkInstance *instance;

	for (instance = dpdkc->instances; instance; instance = instance->next)
	{
		if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
			return DAQ_ERROR;
	}

	dpdkring_daq_reset_stats(handle);
	dpdkc->state = DAQ_STATE_STARTED;

	return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
	DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
	DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
	DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
	DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static int dpdkring_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	DpdkInstance *instance;
	DAQ_PktHdr_t daqhdr;
	DAQ_Verdict verdict;
	const uint8_t *data;
	uint16_t len;
	int c = 0, burst_size;
	int i, got_one, ignored_one, sent_one;
	struct timeval ts;

	while (cnt == 0 || c < cnt)
	{
		struct rte_mbuf *rx_burst[BURST_SIZE];

		got_one = 0;
		ignored_one = 0;
		sent_one = 0;
		
		for (instance = dpdkc->instances; instance; instance = instance->next)
		{
			// Breakloop called ?
			if (dpdkc->break_loop)
			{
				dpdkc->break_loop = 0;
				return 0;
			}
			
			// If there are still some packets to be sent to peer (if in peer mode) then do it
			if (dpdkc->peer_mode)
            {
                burst_size = instance->tx_peer_end - instance->tx_peer_start;
                if (burst_size > 0)
                    goto send_packets;
            }
			
			gettimeofday(&ts, NULL);
			
			// Determine burst size for reading
			if (cnt == 0 || (cnt - c) >= BURST_SIZE)
				burst_size = BURST_SIZE;
			else
				burst_size = cnt - c;
			
			// Read RX ring
			const uint16_t nb_read = rte_ring_dequeue_burst(instance->rx_ring, (void *)rx_burst, burst_size);

			if (unlikely(nb_read == 0))
				continue;
			
			// Process each read packet
			for (i = 0; i < nb_read; i++)
			{
				verdict = DAQ_VERDICT_PASS;

				data = rte_pktmbuf_mtod(rx_burst[i], void *);
				rte_prefetch0(data);
				len = rte_pktmbuf_data_len(rx_burst[i]);

				dpdkc->stats.hw_packets_received++;

				if (dpdkc->fcode.bf_insns && sfbpf_filter(dpdkc->fcode.bf_insns, data, len, len) == 0)
				{
					ignored_one = 1;
					dpdkc->stats.packets_filtered++;
				}
				else
				{
					got_one = 1;

					daqhdr.ts = ts;
					daqhdr.caplen = len;
					daqhdr.pktlen = len;
					daqhdr.ingress_index = instance->ingress_index;
					daqhdr.egress_index = dpdkc->peer_mode ? instance->egress_index : DAQ_PKTHDR_UNKNOWN;
					daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
					daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
					daqhdr.flags = 0;
					daqhdr.opaque = 0;
					daqhdr.priv_ptr = rx_burst[i]->userdata;
					if (daqhdr.priv_ptr != NULL)
						printf("Stream ID = %u\n", daqhdr.priv_ptr);
					daqhdr.address_space_id = 0;

					if (callback)
					{
						verdict = callback(user, &daqhdr, data);
						if (verdict >= MAX_DAQ_VERDICT)
							verdict = DAQ_VERDICT_PASS;
						dpdkc->stats.verdicts[verdict]++;
						verdict = verdict_translation_table[verdict];
					}
					
					dpdkc->stats.packets_received++;
					c++;
				}

				if (verdict == DAQ_VERDICT_PASS && dpdkc->peer_mode)
				{
					instance->tx_peer_burst[instance->tx_peer_end] = rx_burst[i];
					instance->tx_peer_end++;
				}
				else
				{
					rte_pktmbuf_free(rx_burst[i]);
				}
			}
			
			if (dpdkc->peer_mode)
			{
				burst_size = instance->tx_peer_end - instance->tx_peer_start;
				if (unlikely(burst_size == 0))
					continue;
send_packets:
				; //empty statement to avoid compiler error "a label can only be part of a statement and a declaration is not a statement"
				const uint16_t nb_sent = rte_ring_enqueue_burst(instance->tx_ring_peer, (void *)&instance->tx_peer_burst[instance->tx_peer_start], burst_size);
				
				// If nothing has been sent then go to next instance (will try again after when back to current instance)
				if (unlikely(nb_sent == 0))
					continue;
				
				sent_one = 1;
				instance->tx_peer_start += nb_sent;
				
				// If everything has been sent then reset peer indexes
				if (instance->tx_peer_start == instance->tx_peer_end)
				{
					instance->tx_peer_start = 0;
					instance->tx_peer_end = 0;
				}
			}
		}
		
		if ((!got_one && !ignored_one && !sent_one))
        {
            struct timeval now;

            if (dpdkc->timeout == -1)
                continue;

            /* If time out, return control to the caller. */
            gettimeofday(&now, NULL);
            if (now.tv_sec > ts.tv_sec || (now.tv_usec - ts.tv_usec) > dpdkc->timeout * 1000)
			{
                return 0;
			}
        }
        else
        {
            gettimeofday(&ts, NULL);
        }
	}

	return 0;
}

static int dpdkring_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	DpdkInstance *instance;
	struct rte_mbuf *m;

	/* Find the instance that the packet was received on. */
	for (instance = dpdkc->instances; instance; instance = instance->next)
	{
		if (instance->ingress_index == hdr->ingress_index)
			break;
	}

	if (!instance)
	{
		DPE(dpdkc->errbuf, "%s: Unrecognized ingress interface specified: %u", __FUNCTION__, hdr->ingress_index);
		return DAQ_ERROR_NODEV;
	}

	if (!reverse && !dpdkc->peer_mode)
	{
		DPE(dpdkc->errbuf, "%s: Specified ingress interface (%u) has no peer for forward injection.", __FUNCTION__, hdr->ingress_index);
		return DAQ_ERROR_NODEV;
	}

	m = rte_pktmbuf_alloc(instance->mbuf_pool);
	if (!m)
	{
		DPE(dpdkc->errbuf, "%s: Cannot allocate memory for packet.", __FUNCTION__);
		return DAQ_ERROR_NOMEM;
	}

	rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);
	uint16_t nb_sent = rte_ring_enqueue((reverse ? instance->tx_ring_reverse : instance->tx_ring_peer), (void *)m);

	if (unlikely(nb_sent == 0))
	{
		DPE(dpdkc->errbuf, "%s: Cannot send packet. Try again.", __FUNCTION__);
		rte_pktmbuf_free(m);
		return DAQ_ERROR_AGAIN;
	}

	return DAQ_SUCCESS;
}

static int dpdkring_daq_breakloop(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	dpdkc->break_loop = 1;
	return DAQ_SUCCESS;
}

static int dpdkring_daq_stop(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	dpdk_close(dpdkc);
	return DAQ_SUCCESS;
}

static void dpdkring_daq_shutdown(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	dpdk_close(dpdkc);
	
	if (dpdkc->device)
		free(dpdkc->device);
	
	if (dpdkc->filter)
		free(dpdkc->filter);
	
	free(dpdkc);
}

static DAQ_State dpdkring_daq_check_status(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	return dpdkc->state;
}

static int dpdkring_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	rte_memcpy(stats, &dpdkc->stats, sizeof(DAQ_Stats_t));
	return DAQ_SUCCESS;
}

static void dpdkring_daq_reset_stats(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	memset(&dpdkc->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdkring_daq_get_snaplen(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	return dpdkc->snaplen;
}

static uint32_t dpdkring_daq_get_capabilities(void *handle)
{
	return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
		DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
		DAQ_CAPA_DEVICE_INDEX;
}

static int dpdkring_daq_get_datalink_type(void *handle)
{
	return DLT_EN10MB;
}

static const char *dpdkring_daq_get_errbuf(void *handle)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	return dpdkc->errbuf;
}

static void dpdkring_daq_set_errbuf(void *handle, const char *string)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;

	if (!string)
		return;

	DPE(dpdkc->errbuf, "%s", string);
}

static int dpdkring_daq_get_device_index(void *handle, const char *device)
{
	Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
	DpdkInstance *instance;
	int index;

	if (strncmp(device, "dpdk", 4) != 0 || sscanf(&device[4], "%d", &index) != 1)
		return DAQ_ERROR_NODEV;

	for (instance = dpdkc->instances; instance; instance = instance->next)
	{
		if (instance->ingress_index == index)
			return instance->ingress_index;
	}

	return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdkring_daq_module_data =
#endif
{
	/* .api_version = */ DAQ_API_VERSION,
	/* .module_version = */ DAQ_DPDK_VERSION,
	/* .name = */ "dpdkring",
	/* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
	/* .initialize = */ dpdkring_daq_initialize,
	/* .set_filter = */ dpdkring_daq_set_filter,
	/* .start = */ dpdkring_daq_start,
	/* .acquire = */ dpdkring_daq_acquire,
	/* .inject = */ dpdkring_daq_inject,
	/* .breakloop = */ dpdkring_daq_breakloop,
	/* .stop = */ dpdkring_daq_stop,
	/* .shutdown = */ dpdkring_daq_shutdown,
	/* .check_status = */ dpdkring_daq_check_status,
	/* .get_stats = */ dpdkring_daq_get_stats,
	/* .reset_stats = */ dpdkring_daq_reset_stats,
	/* .get_snaplen = */ dpdkring_daq_get_snaplen,
	/* .get_capabilities = */ dpdkring_daq_get_capabilities,
	/* .get_datalink_type = */ dpdkring_daq_get_datalink_type,
	/* .get_errbuf = */ dpdkring_daq_get_errbuf,
	/* .set_errbuf = */ dpdkring_daq_set_errbuf,
	/* .get_device_index = */ dpdkring_daq_get_device_index,
	/* .modify_flow = */ NULL,
	/* .hup_prep = */ NULL,
	/* .hup_apply = */ NULL,
	/* .hup_post = */ NULL,
	/* .dp_add_dc = */ NULL
};
