#ifndef __BOND_NLB_H__
#define __BOND_NLB_H__

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ktime.h>
#include "bonding.h"

#define NLB_MAX_SLAVES 4
#define NLB_REPORT_COUNT 50000
#define BOND_NLB_INFO(bond) ((bond)->nlb_info)
#define PKT_TYPE_BOND cpu_to_be16(0x8810)
#define PKT_TYPE_BOND_HELLO cpu_to_be16(0x8812)
#define PKT_TYPE_BOND_CONTROL cpu_to_be16(0x8811)
#define BOND_NLB_MAX_SEQ 1000000
#define BOND_NLB_HELLO_INTERVAL 10000			// 10 seconds
#define BOND_NLB_CHECK_INTERVAL 3000			// 3 second
#define BOND_NLB_B2B_THRESH 1000				// 1 msec (unit: microseconds)
#define BOND_NLB_UPDATE_THRESH 500				
#define BOND_NLB_HOLD_TIME 200000				// 100 msec (unit: microseconds)
//#define BOND_NLB_HOLD_TIME 5000000

#define ACTION_TYPE_TX 0
#define ACTION_TYPE_RX 1
#define ACTION_TYPE_ACCEPT 2

// nlb header ------------------------------------------------------------------
#define BOND_NLB_HLEN 16
#pragma pack(1)
struct bondnlbhdr {

	unsigned char src_addr[ETH_ALEN];
	__be16 protocol;
	__be32 local_seq;	// MSB of this variable will be used as the "B" flag.
	__be32 global_seq;
};
#pragma pack()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// hello header 
#pragma pack(1)
typedef struct hello_marker {
	unsigned char addr[ETH_ALEN];
} __packed hello_marker_t;

typedef struct hello_marker_header {
	struct ethhdr hdr;
	struct hello_marker marker;
	u8 padding[ETH_ZLEN - ETH_HLEN - sizeof(struct hello_marker)];
} __packed hello_marker_header_t;
#pragma pack()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// control header
#pragma pack(1)
typedef struct control_marker {
	unsigned char addr[ETH_ALEN];
	u32 schedule[NLB_MAX_SLAVES];
} __packed control_marker_t;

typedef struct control_marker_header {
	struct ethhdr hdr;
	struct control_marker marker;
	u8 padding [ETH_ZLEN - ETH_HLEN - sizeof(struct control_marker)];
} __packed control_marker_header_t;
#pragma pack()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
struct nlb_neighbor_info {
	// mac address of the neighbor
	unsigned char addr[ETH_ALEN];

	// recv queue for in-order delivery
	struct sk_buff_head recv_queue;

	// sequence numbers
	u32 seq_tx_global;
	u32 seq_tx_local[NLB_MAX_SLAVES];

	u32 seq_rx_global;
	u32 seq_rx_local[NLB_MAX_SLAVES];

	u32 seq_rx_local_last[NLB_MAX_SLAVES];
	ktime_t seq_rx_local_last_time[NLB_MAX_SLAVES];

	ktime_t prev_tx_time[NLB_MAX_SLAVES];

	u32 rx_gap_total[NLB_MAX_SLAVES];
	u32 rx_gap_count[NLB_MAX_SLAVES];

	u32 tx_schedule[NLB_MAX_SLAVES];
	u32 rx_schedule[NLB_MAX_SLAVES];

	u32 tx_counter[NLB_MAX_SLAVES];
	u32 rx_counter[NLB_MAX_SLAVES];

	// timer
	struct delayed_work nlb_timeout_work;

	// debugfs directory
	struct dentry *nlb_debug_dir;

	u32 param_auto_schedule;
	u32 param_inorder_delivery;

	// link to the bonding structure
	struct bonding *bond;

	struct list_head list;
};
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// data structure for NLB mode 
struct nlb_bond_info {

	// lock for this data structure
	spinlock_t nlb_lock;

	//--------------------------------------------------------------------------
	// DEBUG FILE SYSTEM
	// tx and rx counter for each slave
	u32 tx_counter[NLB_MAX_SLAVES];
	u32 rx_counter[NLB_MAX_SLAVES];

	// per-packet statistics (currently 42 bytes per packet)
	ktime_t	tstamp[NLB_REPORT_COUNT];	// ktime_t is 8 bytes (64 bits).
	u32     len[NLB_REPORT_COUNT];
	u16		txrx[NLB_REPORT_COUNT];
	u16		tcpsport[NLB_REPORT_COUNT];
	u16		tcpdport[NLB_REPORT_COUNT];
	u32		tcpseqnum[NLB_REPORT_COUNT];
	u32		tcpacknum[NLB_REPORT_COUNT];
	u16		interface[NLB_REPORT_COUNT];
	u16		protocol[NLB_REPORT_COUNT];
	u32		bondlocalseq[NLB_REPORT_COUNT];
	u32		bondglobalseq[NLB_REPORT_COUNT];
	u16		backtoback[NLB_REPORT_COUNT];

	//--------------------------------------------------------------------------
	// packet schedules (DEPRECATED)
	u32		pkts_slave[NLB_MAX_SLAVES];
	//--------------------------------------------------------------------------

	//--------------------------------------------------------------------------
	// PACKET SCHEDULING AND IN-ORDER DELIVERY (DEPRECATED)
	// sequence number (temporary, need to have sequence number per neighbor)
	u32		seq;

	ktime_t prev_send_time[NLB_MAX_SLAVES];
	u32		prev_seq[NLB_MAX_SLAVES];
	ktime_t prev_recv_time[NLB_MAX_SLAVES];
	u32		delay_total[NLB_MAX_SLAVES];
	u32		delay_count[NLB_MAX_SLAVES];
	//--------------------------------------------------------------------------

	//--------------------------------------------------------------------------
	// list of nlb_neighbor_info
	struct list_head neighbor_list;

	//--------------------------------------------------------------------------
	// debug file system related
	struct dentry *nlb_station_debug_dir;
};
//------------------------------------------------------------------------------
	

// TX/RX functions -------------------------------------------------------------
void bond_nlb_initialize(struct bonding *bond);
void bond_nlb_deinitialize(struct bonding *bond);
u32  bond_nlb_gen_slave_id(struct bonding *bond, const u8 *dest);
int  bond_nlb_xmit(struct sk_buff *skb, struct net_device *bond_dev);
void bond_xmit_nlb_slave_id(struct bonding *bond, struct sk_buff *skb, int slave_id);
int  bond_nlb_recv(struct sk_buff *skb, struct bonding *bond, struct slave *slave);
//------------------------------------------------------------------------------

void bond_nlb_process_hello(struct bonding *bond, struct hello_marker *marker);
void bond_nlb_process_control(struct bonding *bond, struct control_marker *marker);
void bond_nlb_create_neighbor_info(struct bonding *bond, const u8 *addr);
bool bond_nlb_is_neighbor(struct bonding *bond, const u8 *addr);
struct nlb_neighbor_info* bond_nlb_get_neighbor_info(struct bonding *bond, const u8 *addr);
void bond_nlb_send_control(struct bonding *bond, struct nlb_neighbor_info *ni);

void bond_nlb_insert_to_queue(struct bonding *bond, struct nlb_neighbor_info *ni, struct sk_buff *skb);
void bond_nlb_process_queue(struct bonding *bond, struct nlb_neighbor_info *ni, bool timeout);

void bond_nlb_accept_packets_immediately(struct bonding *bond, struct nlb_neighbor_info *ni);

bool bond_nlb_skb_timeout(struct sk_buff *skb);
u32  bond_nlb_skb_timeout_left(struct sk_buff *skb);

// Functions related to debug file system --------------------------------------
void bond_dfs_write(struct bonding *bond, struct sk_buff *skb, int slave_id, int txrx, u32 global_seq, u32 local_seq, int backtoback);
//------------------------------------------------------------------------------

// Functions related to nlb header ---------------------------------------------
void bond_nlb_attach_header(struct bonding *bond, struct sk_buff *skb, int slave_id, u32 backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr);
void bond_nlb_detach_header(struct bonding *bond, struct sk_buff *skb, int *backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr);
void bond_nlb_peek_header(struct bonding *bond, struct sk_buff *skb, int *backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr);
u32 bond_nlb_read_global_seq(struct bonding *bond, struct sk_buff *skb);
u32 bond_nlb_read_local_seq(struct bonding *bond, struct sk_buff *skb);
//------------------------------------------------------------------------------

// Functions for debugging -----------------------------------------------------
void bond_debug_packet_hex(struct sk_buff *skb);

// Timer handlers --------------------------------------------------------------
void bond_nlb_check_handler(struct work_struct *work);
void bond_nlb_hello_handler(struct work_struct *work);
void bond_nlb_timeout_handler(struct work_struct *work);



// Functions related to in-order delivery --------------------------------------
//void bond_nlb_insert_skb_queue_sorted(struct bonding *bond, struct sk_buff_head *list, struct sk_buff *skb);
//------------------------------------------------------------------------------
#endif
