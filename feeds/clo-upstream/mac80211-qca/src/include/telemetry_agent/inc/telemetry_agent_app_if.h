/*
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef __TELEMETRY_AGENT_APP_IF_H__
#define __TELEMETRY_AGENT_APP_IF_H__

#define MAX_SOCS 5
#define MAX_PDEV_LINKS 2
#define NUM_TIDS 8
#define RFS_INIT_DATA 1
#define RFS_STATS_DATA 2
#define RFS_DYNAMIC_INIT_DATA 3
#define WLAN_VENDOR_EHTCAP_TXRX_MCS_NSS_IDX_MAX 4
#define MAX_T2LM_INFO 2
#define WLAN_AC_MAX 4

#ifdef CONFIG_KASAN
/* reducing for KASAN to avoid bloating issue */
#define MAX_PEERS 100
#else
#define MAX_PEERS 512
#endif

#define MU_MAX_USERS 37
#define MUMIMO_MAX_USERS 8
#define SAWF_MAXQ_PTID 2
#define SAWF_MAX_QUEUES (NUM_TIDS * SAWF_MAXQ_PTID)

/*
   Buffer Format
   --------------------------------------------
   |          |                  |            |
   |  HEADER  |  Payload (stats) | Tail Data  |
   |          |                  |            |
   --------------------------------------------
 */

struct emesh_peer_stats {
    uint8_t peer_link_mac[6];
    uint16_t tx_airtime_consumption[WLAN_AC_MAX];
};

struct emesh_link_stats {
    uint8_t link_mac[6];
    uint8_t link_idle_airtime;
    int num_peers;
    struct emesh_peer_stats peer_stats[MAX_PEERS];
};

struct emesh_soc_stats {
    int num_links;
    struct emesh_link_stats link_stats[MAX_PDEV_LINKS];
};


struct emesh_relyfs_stats {
    int num_soc;
    struct emesh_soc_stats soc_stats[MAX_SOCS];
};

enum tx_mode_dl {
    TX_DL_SU_DATA = 0,
    TX_DL_OFDMA_DATA,
    TX_DL_MUMIMO_DATA,
    TX_DL_MAX,
};

enum tx_mode_ul {
    TX_UL_OFDMA_BASIC_TRIGGER_DATA = 0,
    TX_UL_MUMIMO_BASIC_TRIGGER_DATA,
    TX_UL_OFDMA_MU_BAR_TRIGGER,
    TX_UL_MAX,
};

enum msduq_index {
    MSDUQ_DEFAULT = 0,
    MSDUQ_CUSTOM_PRIO_0,
    MSDUQ_CUSTOM_PRIO_1,
    MSDUQ_CUSTOM_EXT_PRIO_0,
    MSDUQ_CUSTOM_EXT_PRIO_1,
    MSDUQ_CUSTOM_EXT_PRIO_2,
    MSDUQ_CUSTOM_EXT_PRIO_3,
    MSDUQ_MAX,
};

/* peer level stats are commented out due to bloating issue for now */
/*
struct deter_peer_tx_dl {
    uint64_t avg_rate;
    uint32_t mode_cnt;
};

struct deter_peer_tx_ul {
    uint64_t avg_rate;
    uint32_t mode_cnt;
    uint32_t trigger_success;
    uint32_t trigger_fail;
};

struct deter_peer_rx {
    uint64_t avg_rate;
    uint32_t mode_cnt;
};

struct deter_peer_iface_stats {
    struct deter_peer_tx_dl dl_det[MSDUQ_MAX][TX_DL_MAX];
    struct deter_peer_tx_ul ul_det[TX_UL_MAX];
    struct deter_peer_rx rx_det;
};

struct deter_peer_stats {
    uint8_t peer_link_mac[6];
    uint8_t vdev_id;
    struct deter_peer_iface_stats deter[NUM_TIDS];
}; */

struct deter_link_chan_util_stats {
    uint8_t chan_util;
    uint8_t tx_util;
    uint8_t rx_util;
};

struct deter_link_ul_trigger_status {
    uint64_t trigger_success;
    uint64_t trigger_fail;
};

struct deter_link_stats {
    uint8_t link_mac[6];
    uint8_t hw_link_id;
    uint32_t num_peers;
    uint64_t dl_ofdma_usr[MU_MAX_USERS];
    uint64_t ul_ofdma_usr[MU_MAX_USERS];
    uint64_t dl_mimo_usr[MUMIMO_MAX_USERS];
    uint64_t ul_mimo_usr[MUMIMO_MAX_USERS];
    uint64_t dl_mode_cnt[TX_DL_MAX];
    uint64_t ul_mode_cnt[TX_UL_MAX];
    uint64_t rx_su_cnt;
    uint32_t ch_access_delay[WLAN_AC_MAX];
    struct deter_link_chan_util_stats ch_util;
    struct deter_link_ul_trigger_status ts[TX_UL_MAX];
    // struct deter_peer_stats peer_stats[MAX_PEERS];
};

struct deter_soc_stats {
    uint8_t num_links;
    uint8_t soc_id;
    struct deter_link_stats link_stats[MAX_PDEV_LINKS];
};

struct deter_periodic_stats {
    uint8_t num_soc;
    struct deter_soc_stats soc_stats;
};

struct telemetry_agent_header {
	u_int32_t   start_magic_num;
	u_int32_t   stats_version;
	u_int32_t   stats_type;
	u_int32_t   payload_len;
} __attribute__ ((__packed__));

struct telemetry_emesh_buffer {
        struct telemetry_agent_header header;
        struct emesh_relyfs_stats relayfs_stats;
        u_int32_t   end_magic_num;
};

struct telemetry_deter_buffer {
        struct telemetry_agent_header header;
        struct deter_periodic_stats relayfs_stats;
        u_int32_t   end_magic_num;
};

struct erp_link_stats {
	uint64_t tx_data_msdu_cnt;
	uint64_t rx_data_msdu_cnt;
	uint64_t total_tx_data_bytes;
	uint64_t total_rx_data_bytes;
	uint8_t sta_vap_exist;
	uint64_t time_since_last_assoc;
};

struct erp_soc_stats {
	uint8_t num_links;
	struct erp_link_stats link_stats[MAX_PDEV_LINKS];
};

struct erp_relayfs_stats {
	uint8_t num_soc;
	struct erp_soc_stats soc_stats[MAX_SOCS];
};

struct telemetry_erp_buffer {
	struct telemetry_agent_header header;
	struct erp_relayfs_stats relayfs_stats;
	uint32_t end_magic_num;
};

struct admctrl_msduq_stats {
    uint64_t tx_success_num;
};

struct admctrl_peer_stats {
    uint8_t peer_link_mac[6];
    uint8_t peer_mld_mac[6];
    uint8_t is_assoc_link;
    uint8_t tx_airtime_consumption[WLAN_AC_MAX];
    uint64_t tx_success_num;
    uint64_t mld_tx_success_num;
    uint64_t avg_tx_rate;
    struct admctrl_msduq_stats msduq_stats[SAWF_MAX_QUEUES];
};

struct admctrl_link_stats {
    uint16_t hw_link_id;
    uint8_t freetime;
    uint8_t tx_link_airtime[WLAN_AC_MAX];
    uint16_t num_peers;
    struct admctrl_peer_stats peer_stats[MAX_PEERS];
};

struct admctrl_soc_stats {
	uint8_t soc_id;
	uint8_t num_links;
	struct admctrl_link_stats link_stats[MAX_PDEV_LINKS];
};

struct admctrl_relyfs_stats {
	uint8_t num_soc;
	struct admctrl_soc_stats soc_stats[MAX_SOCS];
};

struct telemetry_admctrl_buffer {
        struct telemetry_agent_header header;
        struct admctrl_relyfs_stats relayfs_stats;
        u_int32_t end_magic_num;
};

enum wlan_vendor_channel_width {
	WLAN_VENDOR_CHAN_WIDTH_INVALID = 0,
	WLAN_VENDOR_CHAN_WIDTH_20MHZ = 1,
	WLAN_VENDOR_CHAN_WIDTH_40MHZ = 2,
	WLAN_VENDOR_CHAN_WIDTH_80MHZ = 3,
	WLAN_VENDOR_CHAN_WIDTH_160MZ = 4,
	WLAN_VENDOR_CHAN_WIDTH_80_80MHZ = 5,
	WLAN_VENDOR_CHAN_WIDTH_320MHZ = 6,
};

enum t2lm_band_caps {
	T2LM_BAND_INVALID,
	T2LM_BAND_2GHz,
	T2LM_BAND_5GHz,
	T2LM_BAND_5GHz_LOW,
	T2LM_BAND_5GHz_HIGH,
	T2LM_BAND_6Ghz,
	T2LM_BAND_6Ghz_LOW,
	T2LM_BAND_6GHz_HIGH,
};

enum wlan_vendor_t2lm_direction {
    WLAN_VENDOR_T2LM_INVALID_DIRECTION = 0,
    WLAN_VENDOR_T2LM_DOWNLINK_DIRECTION = 1,
    WLAN_VENDOR_T2LM_UPLINK_DIRECTION = 2,
    WLAN_VENDOR_T2LM_BIDI_DIRECTION = 3,
    WLAN_VENDOR_T2LM_MAX_VALID_DIRECTION =
        WLAN_VENDOR_T2LM_BIDI_DIRECTION,
};

struct aa_estimation_stats {
	uint32_t traffic_condition[WLAN_AC_MAX];
	uint32_t error_margin[WLAN_AC_MAX];
	uint32_t num_dl_asymmetric_clients[WLAN_AC_MAX];
	uint32_t num_ul_asymmetric_clients[WLAN_AC_MAX];
	uint8_t dl_payload_ratio[WLAN_AC_MAX];
	uint8_t ul_payload_ratio[WLAN_AC_MAX];
	uint32_t avg_chan_latency[WLAN_AC_MAX];
};

struct agent_peer_stats {
	uint8_t peer_mld_mac[6];
	uint8_t peer_link_mac[6];
	uint8_t airtime_consumption[WLAN_AC_MAX];
	uint8_t m1_stats;
	uint8_t m2_stats;
	int8_t snr;
	int16_t eff_chan_bw;
	uint16_t sla_mask; /* Uses telemetry_sawf_param for bitmask */
};

struct agent_link_stats {
	uint16_t hw_link_id;
	uint8_t link_airtime[WLAN_AC_MAX];
	uint8_t freetime;
	uint8_t obss_airtime;
	uint8_t available_airtime[WLAN_AC_MAX];
	uint32_t m3_stats[WLAN_AC_MAX];
	uint32_t m4_stats[WLAN_AC_MAX];
	uint16_t num_peers;
	struct aa_estimation_stats aa_est;
	struct agent_peer_stats peer_stats[MAX_PEERS];
};

struct agent_soc_stats {
	uint8_t soc_id;
	uint16_t num_peers;
	uint8_t num_links;
	struct agent_link_stats link_stats[MAX_PDEV_LINKS];
};

/* Periodic Stats */
struct relayfs_stats {
	uint8_t num_soc;
	struct agent_soc_stats soc_stats[MAX_SOCS];
};

struct energysvc_peer_stats {
	uint8_t peer_mld_mac[6];
	uint8_t peer_link_mac[6];
	uint8_t airtime_consumption[WLAN_AC_MAX];
	uint16_t tx_airtime_consumption[WLAN_AC_MAX];
	uint16_t sla_mask; /* Uses telemetry_sawf_param for bitmask */
};

struct energysvc_link_stats {
	uint16_t hw_link_id;
	uint16_t freetime;
	uint8_t link_airtime[WLAN_AC_MAX];
	uint8_t available_airtime[WLAN_AC_MAX];
	uint16_t num_peers;
	uint16_t freq;
	bool is_mon_enabled;
	struct energysvc_peer_stats peer_stats[MAX_PEERS];
};

struct energysvc_soc_stats {
	int soc_id;
	int num_links;
	struct energysvc_link_stats link_stats[MAX_PDEV_LINKS];
};

struct energysvc_relyfs_stats {
	int num_soc;
	struct energysvc_soc_stats soc_stats[MAX_SOCS];
};

struct telemetry_energysvc_buffer {
	struct telemetry_agent_header header;
	struct energysvc_relyfs_stats relayfs_stats;
	u_int32_t end_magic_num;
};

/*
 * Init time interface information - complete view.
 */

struct link_map_of_tids {
	enum wlan_vendor_t2lm_direction direction; /* 0-DL, 1-UL, 2-BiDi */
	uint8_t default_link_mapping;
	uint8_t tid_present[NUM_TIDS]; /* TID present on this link */
};

struct agent_msduq_info {
	uint8_t is_used;
	uint8_t svc_id;
	uint8_t svc_type;
	uint8_t svc_tid;
	uint8_t svc_ac;
	uint8_t priority;
	uint32_t service_interval;
	uint32_t burst_size;
	uint32_t min_throughput;
	uint32_t delay_bound;
	uint32_t mark_metadata;
};

struct agent_peer_init_stats {
	uint8_t mld_mac_addr[6];      /* peer MLD mac */
	uint8_t link_mac_addr[6];     /* peer MLD link mac */
	uint8_t is_assoc_link;
	int ifindex;
	uint8_t vdev_id;              /* peer vdev id */
	uint8_t ap_mld_addr[6];       /* AP MLD mac */
	struct link_map_of_tids t2lm_info[MAX_T2LM_INFO]; /* T2LM mapping */
	enum wlan_vendor_channel_width chan_bw;
	uint16_t chan_freq;                  /* channel center frequency */
	uint32_t tx_mcs_nss_map[WLAN_VENDOR_EHTCAP_TXRX_MCS_NSS_IDX_MAX];
	uint32_t rx_mcs_nss_map[WLAN_VENDOR_EHTCAP_TXRX_MCS_NSS_IDX_MAX];
	uint8_t ieee_link_id;
	uint16_t disabled_link_bitmap;
	uint16_t peer_flags;
	struct agent_msduq_info msduq[SAWF_MAX_QUEUES];
};

struct agent_link_init_stats {
	uint16_t hw_link_id;
	/* enum t2lm_band_caps band; */
	uint16_t num_peers;
	struct agent_peer_init_stats peer_stats[MAX_PEERS];
};

struct agent_soc_init_stats {
	uint8_t soc_id;
	uint16_t num_peers;
	uint8_t num_links;
	struct agent_link_init_stats link_stats[MAX_PDEV_LINKS];
};

struct relayfs_init_stats {
	uint8_t num_soc;
	struct agent_soc_init_stats soc_stats[MAX_SOCS];
};

struct telemetry_pmlo_buffer {
	struct telemetry_agent_header header;
	struct relayfs_stats periodic_stats;
	u_int32_t end_magic_num;
};

struct telemetry_rm_main_buffer {
	struct telemetry_agent_header header;
	struct relayfs_init_stats init_stats;
	u_int32_t end_magic_num;
};

enum rm_services {
	RM_MAIN_SERVICE = 0,
	RM_PMLO_SERVICE,
	RM_DETSCHED_SERVICE,
	RM_ERP_SERVICE,
	RM_ADMCTRL_SERVICE,
	RM_ENERGY_SERVICE,
	RM_IFLI_PROXY_SERVICE,
	RM_POWER_BOOST_SERVICE,
	RM_MAX_SERVICE,
};

#endif /* __TELEMETRY_AGENT_APP_IF_H__ */
