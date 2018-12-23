#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/if_bonding.h>
#include <linux/pkt_sched.h>
#include <net/net_namespace.h>
#include "bonding.h"
#include "bond_nlb.h"
#include <linux/time.h>
#include <net/route.h>

#ifndef __long_aligned
#define __long_aligned __attribute__((aligned((sizeof(long)))))
#endif
static const u8 mac_bcast[ETH_ALEN] __long_aligned = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

// initilize function for NLB mode ---------------------------------------------
void bond_nlb_initialize(struct bonding *bond) {
	
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));	
	int i;
	
	// lock data
	spin_lock_bh(&info->nlb_lock);

	// initialize counters
	for(i=0; i<NLB_MAX_SLAVES; i++) {
		info->tx_counter[i] = 0;
		info->rx_counter[i] = 0;
		info->pkts_slave[i] = 0;

		info->prev_send_time[i] = ktime_get();
		info->prev_recv_time[i] = ktime_get();
		info->prev_seq[i] = 0;
		info->delay_total[i] = 0;
		info->delay_count[i] = 0;
	}
	info->pkts_slave[0] = 1;		// default packet schedule: only slave 0
	info->seq = 1;					// initial sequence number: 0

	// initialize neighbor list
	INIT_LIST_HEAD(&info->neighbor_list);
	
	// unlock data
	spin_unlock_bh(&info->nlb_lock);

	//net_enable_timestamp();

	// initialize delayed_works
	INIT_DELAYED_WORK(&bond->nlb_hello_work, bond_nlb_hello_handler);
	INIT_DELAYED_WORK(&bond->nlb_check_work, bond_nlb_check_handler);

	// activate check timer
	queue_delayed_work(bond->wq, &bond->nlb_check_work, msecs_to_jiffies(BOND_NLB_CHECK_INTERVAL));	// 3 seconds
	queue_delayed_work(bond->wq, &bond->nlb_hello_work, msecs_to_jiffies(BOND_NLB_HELLO_INTERVAL));	// hello interval: 10 seconds

	// create debug file system
	bond_debug_nlb_create_dir(bond);
}
//------------------------------------------------------------------------------

// deinitialize function for NLB mode ------------------------------------------
void bond_nlb_deinitialize(struct bonding *bond) {

	// release all neighbor info
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *n, *tmp;

	spin_lock_bh(&info->nlb_lock);

	list_for_each_entry_safe(n, tmp, &info->neighbor_list, list) {

		bond_nlb_accept_packets_immediately(bond, n);
		cancel_delayed_work_sync(&n->nlb_timeout_work);

		list_del(&n->list);
		kfree(n);	
	}

	spin_unlock_bh(&info->nlb_lock);

	// cancel all timers
	cancel_delayed_work_sync(&bond->nlb_check_work);
	cancel_delayed_work_sync(&bond->nlb_hello_work);

	//net_disable_timestamp();
}
//------------------------------------------------------------------------------

// utility function to generate the next slave id ------------------------------
u32 bond_nlb_gen_slave_id(struct bonding *bond, const u8 *dest) {

	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *ni = NULL;
	u32 slave_id = 0;
	int i, sum, iter;
	int ret = 0;

	ni = bond_nlb_get_neighbor_info(bond, dest);
	if(ni == NULL) return 0;	

	slave_id = ni->seq_tx_global;

	// decide interface based on packet schedule -------------------------------
	spin_lock_bh(&info->nlb_lock);

	sum = 0;
	for(i=0; i<slave_cnt; i++) sum += ni->tx_schedule[i];

	iter = 0;
	for(i=0; i<slave_cnt; i++) {
		iter += ni->tx_schedule[i];
		if(slave_id % sum < iter) {
			ret = i;
			break;
		}
	}

	spin_unlock_bh(&info->nlb_lock);	

	return ret;
}
//------------------------------------------------------------------------------

// transmit function: upper part -----------------------------------------------
int bond_nlb_xmit(struct sk_buff *skb, struct net_device *bond_dev) {

	struct bonding *bond = netdev_priv(bond_dev);
	struct ethhdr *eth = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct slave *slave;
	u32 slave_id = 0;

	// special processing for IGMP packets -------------------------------------
	if(iph->protocol == IPPROTO_IGMP && skb->protocol == htons(ETH_P_IP)) {
		slave = rcu_dereference(bond->curr_active_slave);
		if(slave) bond_dev_queue_xmit(bond, skb, slave->dev);
		else bond_xmit_nlb_slave_id(bond, skb, 0);
	}
	// general processing ------------------------------------------------------
	else {
		int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
		
		if(likely(slave_cnt)) {
			slave_id = bond_nlb_gen_slave_id(bond, eth->h_dest);
			bond_xmit_nlb_slave_id(bond, skb, slave_id % slave_cnt);
		} else {
			dev_kfree_skb_any(skb);
		}	
	}

	return NETDEV_TX_OK;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// transmit function: lower part 
void bond_xmit_nlb_slave_id(struct bonding *bond, struct sk_buff *skb, int slave_id) {
	
	struct list_head *iter;
	struct slave *slave;
	int i = slave_id;
	u32 global_seq = 0;
	u32 local_seq = 0;
	struct ethhdr *eth = (struct ethhdr*)skb->data;
	struct nlb_neighbor_info *ni;
	ktime_t now, diff;
	struct timeval tv;
	u32 diffnum;
	int flag = 0;

	if(skb->protocol == PKT_TYPE_BOND_CONTROL || skb->protocol == PKT_TYPE_BOND_HELLO) {

	} else {

		//--------------------------------------------------------------------------
		// bonding header is attached only if destination is a neighbor
		if(bond_nlb_is_neighbor(bond, eth->h_dest)) {
			ni = bond_nlb_get_neighbor_info(bond, eth->h_dest);

			//----------------------------------------------------------------------
			// MARK BACK-TO-BACK PACKETS
			now = ktime_get();
			diff = ktime_sub(now, ni->prev_tx_time[slave_id]);
			tv = ktime_to_timeval(diff);
			diffnum = tv.tv_sec * 1000000 + tv.tv_usec;
			if(diffnum < BOND_NLB_B2B_THRESH) flag = 1;
	
			bond_nlb_attach_header(bond, skb, slave_id, flag, &global_seq, &local_seq);

			ni->prev_tx_time[slave_id] = now;
			ni->tx_counter[slave_id]++;
		} else {

		}
	
		// record in debug file system
		bond_dfs_write(bond, skb, slave_id, ACTION_TYPE_TX, global_seq, local_seq, flag);
	}

    /* Here we start from the slave with slave_id */
	// jungmin -----------------------------------------------------------------
	// 1) i is set to the slave_id k
    // 2) count from the first slave, and decrement i
    // 3) if i goes below zero, that is the kth slave
    //--------------------------------------------------------------------------
    bond_for_each_slave_rcu(bond, slave, iter) {
        if (--i < 0) {
            if (bond_slave_can_tx(slave)) {
                bond_dev_queue_xmit(bond, skb, slave->dev);
                return;
            }
        }
    }

    /* Here we start from the first slave up to slave_id */
	// jungmin -----------------------------------------------------------------
    // try to send the packet to any interface from interface 0
    //--------------------------------------------------------------------------
    i = slave_id;
    bond_for_each_slave_rcu(bond, slave, iter) {
        if (--i < 0)
            break;
        if (bond_slave_can_tx(slave)) {
            bond_dev_queue_xmit(bond, skb, slave->dev);
            return;
        }
    }
    /* no slave that can tx has been found */
    dev_kfree_skb_any(skb);
}
//------------------------------------------------------------------------------

void bond_nlb_insert_to_queue(struct bonding *bond, struct nlb_neighbor_info *ni, struct sk_buff *skb) {

	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct sk_buff_head *list = &ni->recv_queue;
	struct sk_buff *curr_skb = skb_peek(list);
	u32 seq = bond_nlb_read_global_seq(bond, skb);
	u32 curr_seq;
	int inserted = 0;

	spin_lock_bh(&info->nlb_lock);

	while(curr_skb) {
		curr_seq = bond_nlb_read_global_seq(bond, curr_skb);
		if(seq < curr_seq) {
			skb_insert(curr_skb, skb, list);
			inserted = 1;
			break;
		}
		curr_skb = skb_peek_next(curr_skb, list);
	}

	if(inserted == 0) {
		skb_queue_tail(list, skb);
	}
	
	spin_unlock_bh(&info->nlb_lock);
}

void bond_nlb_accept_packets_immediately(struct bonding *bond, struct nlb_neighbor_info *ni) {

	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct sk_buff_head *list = &ni->recv_queue;
	struct sk_buff *skb;
	u32 backtoback, global_seq, local_seq;
	int slave_id;

	spin_lock_bh(&info->nlb_lock);
	
	while(skb_queue_len(list) > 0) {
		skb = skb_dequeue(list);
		slave_id = (int)skb->cb[0];
		bond_nlb_detach_header(bond, skb, &backtoback, &global_seq, &local_seq);
		bond_dfs_write(bond, skb, slave_id, ACTION_TYPE_ACCEPT, global_seq, local_seq, backtoback); 
		skb->dev = bond->dev;
		netif_receive_skb(skb);

		if(global_seq >= ni->seq_rx_global) ni->seq_rx_global = global_seq+1;
		if(local_seq >= ni->seq_rx_local[slave_id]) ni->seq_rx_local[slave_id] = local_seq+1;
	}

	spin_unlock_bh(&info->nlb_lock);
}

void bond_nlb_process_queue(struct bonding *bond, struct nlb_neighbor_info *ni, bool timeout) {

	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct sk_buff_head *list = &ni->recv_queue;
	struct sk_buff *skb;
	u32 seq;
	u32 backtoback, global_seq, local_seq;
	bool front_change;
	u32 timeout_left_usec;
	int slave_id;
	int i;

	u32 must_cancel = 0;
	u32 must_reschedule = 0;

	u32 global_gap, local_gap_sum;
	
	spin_lock_bh(&info->nlb_lock);

	if(timeout) printk("bond_nlb_process_queue from timeout qlen: %d\n", skb_queue_len(list));

	//--------------------------------------------------------------------------
	// detect packet loss
	skb = skb_peek_tail(list);
	if(skb != NULL) {
		seq = bond_nlb_read_global_seq(bond, skb);
		if(seq > ni->seq_rx_global) global_gap = seq - ni->seq_rx_global + 1;
		else global_gap = 0;

		local_gap_sum = 0;
		for(i=0; i<slave_cnt; i++) {
			if(ni->seq_rx_local_last[i] > ni->seq_rx_local[i]) {
				local_gap_sum += ni->seq_rx_local_last[i] - ni->seq_rx_local[i] + 1;
			}
		}

		if(seq > ni->seq_rx_global && local_gap_sum >= global_gap) {
			//printk("PACKET LOSS DETECTED - seq_rx_global jumps from %u to %u\n", ni->seq_rx_global, seq);
			printk("JUMPS FROM %u TO %u (l: %d) ggap: %u lgapsum: %u\n", ni->seq_rx_global, seq, skb_queue_len(list), global_gap, local_gap_sum);
			for(i=0; i<slave_cnt; i++) {
				printk("local[%d]: %u last[%d]: %u\n", i, ni->seq_rx_local[i], i, ni->seq_rx_local_last[i]);
			}
			ni->seq_rx_global = seq;
			for(i=0; i<slave_cnt; i++) {
				ni->seq_rx_local[i] = ni->seq_rx_local_last[i]; 
			}
		}
	}
	//--------------------------------------------------------------------------

	front_change = false;
	while(skb_queue_len(list) > 0) {

		// look at the global sequence number
		skb = skb_peek(list);
		seq = bond_nlb_read_global_seq(bond, skb);

		// if the sequence number is the same as seq_rx_global, accept the packet
		if(seq <= ni->seq_rx_global || bond_nlb_skb_timeout(skb)) {
			skb = skb_dequeue(list);
			slave_id = (int)skb->cb[0];
			bond_nlb_detach_header(bond, skb, &backtoback, &global_seq, &local_seq);
			bond_dfs_write(bond, skb, (int)(skb->cb[0]), ACTION_TYPE_ACCEPT, global_seq, local_seq, backtoback);
			skb->dev = bond->dev;
			//if(timeout) printk("accepting packet seq: %u\n", global_seq);
			//printk("ACCEPTING PACKET SEQ: %u\n", global_seq);
			netif_receive_skb(skb);

			if(global_seq >= ni->seq_rx_global) ni->seq_rx_global = global_seq+1;
			if(local_seq >= ni->seq_rx_local[slave_id]) ni->seq_rx_local[slave_id] = local_seq+1;

			front_change = true;

		} else {
			// do not accept packet
			break;
		}
	}

	if(front_change || skb_queue_len(list) == 1) must_cancel = 1;
	if(must_cancel == 1 && skb_queue_len(list) > 0) {
		must_reschedule = 1;
		skb = skb_peek(list);
		timeout_left_usec = bond_nlb_skb_timeout_left(skb);
	}

	if(must_cancel == 1) cancel_delayed_work(&ni->nlb_timeout_work);
	if(must_reschedule == 1) {
		queue_delayed_work(bond->wq, &ni->nlb_timeout_work, usecs_to_jiffies(timeout_left_usec));
	}

	spin_unlock_bh(&info->nlb_lock);
}

//------------------------------------------------------------------------------
// recv function
int bond_nlb_recv(struct sk_buff *skb, struct bonding *bond, struct slave *slave) {

	struct list_head *iter;
	struct slave *s;
	int slave_id;
	struct nlb_neighbor_info *ni;
	struct bondnlbhdr *bh;
	ktime_t now, diff;
	struct timeval tv;
	u32 global_seq = 0;
	u32 local_seq = 0;
	u32 backtoback = 0;
	struct sk_buff_head *list;

	struct hello_marker *hello, _hello;
	struct control_marker *control, _control;

	// find slave_id for the interface where the packet was received -----------
	slave_id = 0;
	bond_for_each_slave(bond, s, iter) {
		if(strcmp(s->dev->name, slave->dev->name) == 0) break;
		slave_id++;
	}

	// detach bonding header if necessary --------------------------------------
	if(skb->protocol == PKT_TYPE_BOND) {
		bh = (struct bondnlbhdr*)skb->data;

		/*
		//----------------------------------------------------------------------
		// TEMPORARY: drop packet with seq 10 on purpose and see what happens
		if(bh->global_seq % 10 == 0) {
			consume_skb(skb);
			return RX_HANDLER_CONSUMED;	
		}
		//----------------------------------------------------------------------
		*/

		// Do not process packet here, just enqueue the packet in the proper queue
		ni = bond_nlb_get_neighbor_info(bond, bh->src_addr);
		if(ni) {
			now = ktime_get();

			global_seq = bh->global_seq;
			local_seq = bh->local_seq;
			backtoback = (local_seq & (1 << 31)) >> 31;
			if(backtoback == 1) local_seq -= (1 << 31);
						
			bond_dfs_write(bond, skb, slave_id, ACTION_TYPE_RX, global_seq, local_seq, backtoback);

			// before storing the packet, record statistics on back-to-back packets
			if(backtoback == 1) {

				if(ni->seq_rx_local_last[slave_id] > 0 && ni->seq_rx_local_last[slave_id] == local_seq - 1) {
					// record rx time gap
					diff = ktime_sub(now, ni->seq_rx_local_last_time[slave_id]);
					tv = ktime_to_timeval(diff);
					ni->rx_gap_total[slave_id] += tv.tv_sec * 1000000 + tv.tv_usec;	
					ni->rx_gap_count[slave_id]++;
				}
			}

			// update information
			ni->seq_rx_local_last[slave_id] = local_seq;
			ni->seq_rx_local_last_time[slave_id] = now;

			// if seq_rx_global or seq_rx_local is not initialized, initialize them here
			if(ni->seq_rx_global == 0) ni->seq_rx_global = global_seq;
			if(ni->seq_rx_local[slave_id] == 0) ni->seq_rx_local[slave_id] = local_seq;
	
			// increment counter
			ni->rx_counter[slave_id]++;

			// mark slave_id in skb
			skb->cb[0] = (u8)slave_id;
			skb->tstamp = now;

			if(ni->param_inorder_delivery == 1) {
				bond_nlb_insert_to_queue(bond, ni, skb);	
				bond_nlb_process_queue(bond, ni, false);
				return RX_HANDLER_CONSUMED;
			} else {
				if(global_seq > ni->seq_rx_global) ni->seq_rx_global = global_seq;
				if(local_seq > ni->seq_rx_local[slave_id]) ni->seq_rx_local[slave_id] = local_seq;

				// sanity check: if the recv queue happens to have any packets, accept them
				list = &ni->recv_queue;
				if(skb_queue_len(list) > 0) bond_nlb_accept_packets_immediately(bond, ni);
			}
		}
	
		// If neighbor info does not exist, just detach header and send up the packet.
		bond_nlb_detach_header(bond, skb, &backtoback, &global_seq, &local_seq);
	}
	else if(skb->protocol == PKT_TYPE_BOND_HELLO) {
		
		hello = skb_header_pointer(skb, 0, sizeof(_hello), &_hello);
		if(!hello) return RX_HANDLER_CONSUMED;

		bond_nlb_process_hello(bond, hello);

		consume_skb(skb);
		return RX_HANDLER_CONSUMED;
	}
	else if(skb->protocol == PKT_TYPE_BOND_CONTROL) {
		control = skb_header_pointer(skb, 0, sizeof(_control), &_control);
		if(!control) return RX_HANDLER_CONSUMED;

		bond_nlb_process_control(bond, control);

		consume_skb(skb);
		return RX_HANDLER_CONSUMED;
	}

	bond_dfs_write(bond, skb, slave_id, ACTION_TYPE_ACCEPT, global_seq, local_seq, backtoback);
	return RX_HANDLER_ANOTHER;
}

void bond_nlb_create_neighbor_info(struct bonding *bond, const u8 *addr) {

	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
    int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	int i;

	// allocate memory for the new neighbor info
	// not understood: GFP_KERNEL option results in a crash. why? because we are inside a lock?
	struct nlb_neighbor_info *ni = kmalloc(sizeof(struct nlb_neighbor_info), GFP_ATOMIC);

	// fill in contents of the new neighbor info
	memcpy(ni->addr, addr, ETH_ALEN);
	skb_queue_head_init(&ni->recv_queue);
	ni->seq_tx_global = 1;	
	for(i=0; i<slave_cnt; i++) {
		ni->seq_tx_local[i] = 1;
	}
	ni->seq_rx_global = 0;
	for(i=0; i<slave_cnt; i++) {
		ni->seq_rx_local[i] = 0;
		ni->seq_rx_local_last[i] = 0;
		ni->seq_rx_local_last_time[i] = ktime_get();

		ni->prev_tx_time[i] = ktime_get();

		ni->rx_gap_total[i] = 0;
		ni->rx_gap_count[i] = 0;

		ni->tx_schedule[i] = 2;		// default schedule: 2
		ni->rx_schedule[i] = 2;

		ni->tx_counter[i] = 0;
		ni->rx_counter[i] = 0;
	}

	ni->param_auto_schedule = 1;		// default: auto schedule
	ni->param_inorder_delivery = 1;		// default: in-order delivery

	// record pointer to bonding
	ni->bond = bond;

	printk("NEW NEIGHBOR DETECTED: %pM\n", &ni->addr);

	// initialize timer
	INIT_DELAYED_WORK(&ni->nlb_timeout_work, bond_nlb_timeout_handler);
	
	// add to neighbor list
	spin_lock_bh(&info->nlb_lock);
	list_add_tail(&ni->list, &info->neighbor_list);
    spin_unlock_bh(&info->nlb_lock);

	bond_debug_nlb_create_station_dir(bond, ni);
	bond_debug_nlb_create_station_files(bond, ni);
}

struct nlb_neighbor_info* bond_nlb_get_neighbor_info(struct bonding *bond, const u8 *addr) {

	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *ret = NULL;
	struct nlb_neighbor_info *n;

	spin_lock_bh(&info->nlb_lock);
	list_for_each_entry(n, &info->neighbor_list, list) {
		if(ether_addr_equal(n->addr, addr)) ret = n;
	}
	spin_unlock_bh(&info->nlb_lock);

	return ret;
}

bool bond_nlb_is_neighbor(struct bonding *bond, const u8 *addr) {
	
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *n;
	bool found = false;

	spin_lock_bh(&info->nlb_lock);
	list_for_each_entry(n, &info->neighbor_list, list) {
		if(ether_addr_equal(n->addr, addr)) found = true;
	}
	spin_unlock_bh(&info->nlb_lock);

	return found;
}

void bond_nlb_process_hello(struct bonding *bond, struct hello_marker *hello) {

	if(!bond_nlb_is_neighbor(bond, hello->addr)) {
		bond_nlb_create_neighbor_info(bond, hello->addr);
	} 
}

void bond_nlb_process_control(struct bonding *bond, struct control_marker *control) {

    int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *ni;
	int i;

	ni = bond_nlb_get_neighbor_info(bond, control->addr);
	if(ni == NULL) return;

	spin_lock_bh(&info->nlb_lock);
	
	for(i=0; i<slave_cnt; i++) {
		ni->tx_schedule[i] = control->schedule[i];
	}

	spin_unlock_bh(&info->nlb_lock);
}

void bond_dfs_write(struct bonding *bond, struct sk_buff *skb, int slave_id, int txrx, u32 global_seq, u32 local_seq, int backtoback) {

    int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
    struct iphdr *iph;
    struct tcphdr *th;
    int i, c;
    struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));

	ktime_t a_time = ktime_get();
	u32 a_len = (u32)skb->len;
	u16 a_type = (u16)txrx;
	u16 a_intf = (u16)slave_id;

	u32 a_gseq 			= global_seq;
	u32 a_lseq 			= local_seq;
	u16 a_b2b 			= (u16)backtoback;

	u16 a_proto 		= 0;
	u16 a_tcp_sport 	= 0;
	u16 a_tcp_dport 	= 0;
	u32 a_tcp_seq 		= 0;
	u32 a_tcp_aseq 		= 0;

	//--------------------------------------------------------------------------
	// retrieve information from the packet
	if(skb->protocol == PKT_TYPE_BOND) {
		// case 1: bonding header is attached
		//printk("DFS: PACKET TYPE NOT SUPPORTED (PKT_TYPE_BOND)\n");	
		iph = (struct iphdr*)(skb->data + BOND_NLB_HLEN); 
		a_proto = iph->protocol;


	} else if(skb->protocol == htons(ETH_P_IP)) {
		// case 2: bonding header is not attached
		iph = ip_hdr(skb);
		a_proto = iph->protocol;
		
		if(iph->protocol == IPPROTO_TCP) {
			if(a_type == ACTION_TYPE_TX) th = tcp_hdr(skb);
			else th = (struct tcphdr*)(skb->data + (ip_hdr(skb)->ihl*4));

			a_tcp_sport = th->source;
			a_tcp_dport = th->dest;
			a_tcp_seq	= th->seq;
			a_tcp_aseq	= th->ack_seq;
		}

	} else if(skb->protocol == PKT_TYPE_BOND_HELLO) {
		return;

	} else if(skb->protocol == PKT_TYPE_BOND_CONTROL) {
		return;

	} else {
		// do nothing: use default values
		//printk("DFS: PACKET TYPE NOT SUPPORTED (%d)\n", skb->protocol);
		return;
	}

    spin_lock_bh(&info->nlb_lock);

    // calculate index number in the arrays ------------------------------------
    c = 0;
    for(i=0; i<slave_cnt; i++) c += info->tx_counter[i] + info->rx_counter[i];
    c = c % NLB_REPORT_COUNT;

	// fill in fields
    info->tstamp[c]         = a_time;
    info->len[c]            = a_len;
    info->txrx[c]           = a_type;        
    info->interface[c]      = a_intf;
	info->protocol[c]		= a_proto;

	info->tcpsport[c]		= a_tcp_sport;
	info->tcpdport[c]		= a_tcp_dport;
	info->tcpseqnum[c]		= a_tcp_seq;
	info->tcpacknum[c]		= a_tcp_aseq;

    info->bondglobalseq[c]  = a_gseq;                
	info->bondlocalseq[c]	= a_lseq;
	info->backtoback[c]		= a_b2b;

    if(a_type == ACTION_TYPE_TX) info->tx_counter[slave_id]++;
	else info->rx_counter[slave_id]++;

    spin_unlock_bh(&info->nlb_lock);
}

void bond_nlb_attach_header(struct bonding *bond, struct sk_buff *skb, int slave_id, u32 backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr) {

	unsigned char *old_data;
	struct ethhdr *eth, ethcopy;
	struct bondnlbhdr *bh;
    struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *ni;

	// 1. Increase headroom ----------------------------------------------------
	// Before this, we have only 2 bytes in the headroom.
	// We increase this headroom by the size of bondnlbhdr
	old_data = skb->data;

	skb_reserve(skb, BOND_NLB_HLEN);

	// 2. Move the data back by BOND_NLB_HLEN bytes ----------------------------
	memmove(skb->data, old_data, skb->len);

	// 3. Move header pointers -------------------------------------------------
	if(skb->ip_summed == CHECKSUM_PARTIAL) {
		skb->csum_start += BOND_NLB_HLEN;
	}
	skb->transport_header += BOND_NLB_HLEN;
	skb->network_header += BOND_NLB_HLEN;
	if(skb_mac_header_was_set(skb)) skb->mac_header += BOND_NLB_HLEN;

	// 4. Detach MAC header ----------------------------------------------------
	skb_pull_inline(skb, ETH_HLEN);

	// 5. Copy Ethernet header to a local variable -----------------------------
	eth = eth_hdr(skb);
	memcpy(&ethcopy, eth, ETH_HLEN);

	// 6. Move the Ethernet header to the front --------------------------------
	memmove(old_data, eth, ETH_HLEN);

    spin_lock_bh(&info->nlb_lock);

	// 7. Attach bonding header. Its protocol field is assigned with the saved value.
	// get neighbor info
	ni = bond_nlb_get_neighbor_info(bond, ethcopy.h_dest);

	bh = (struct bondnlbhdr*)skb_push(skb, BOND_NLB_HLEN);

	memset(bh, 0, BOND_NLB_HLEN);	
	memcpy(bh->src_addr, ethcopy.h_source, ETH_ALEN);
	bh->protocol = ethcopy.h_proto;
	bh->local_seq = ni->seq_tx_local[slave_id]++;	// increment after assign
	bh->global_seq = ni->seq_tx_global++;			// increment after assign

	// prepare return values
	*local_seq_ptr = bh->local_seq;
	*global_seq_ptr = bh->global_seq;

	// set "back-to-back" flag
	if(backtoback) {
		// set the MSB of local sequence number
		bh->local_seq = bh->local_seq | (1 << 31);
	}

	// 8. Attach MAC header ----------------------------------------------------
	eth = (struct ethhdr*)skb_push(skb, ETH_HLEN);
	eth->h_proto = PKT_TYPE_BOND;

	// 9. Update header pointers -----------------------------------------------
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN + BOND_NLB_HLEN);	// this may be unnecessary

    spin_unlock_bh(&info->nlb_lock);
}

u32 bond_nlb_read_global_seq(struct bonding *bond, struct sk_buff *skb) {

	struct bondnlbhdr *bh;

	// sanity check: skb should have bonding header attached
	if(skb->protocol != PKT_TYPE_BOND) {
		printk("ERROR: this function should be called for packets with bonding header\n");
		return 0;
	}

	bh = (struct bondnlbhdr*)skb->data;
	return bh->global_seq;
}

u32 bond_nlb_read_local_seq(struct bonding *bond, struct sk_buff *skb) {

	struct bondnlbhdr *bh;
	u32 ret;
	u32 flag;

	// sanity check: skb should have bonding header attached
	if(skb->protocol != PKT_TYPE_BOND) {
		printk("ERROR: this function should be called for packets with bonding header\n");
		return 0;
	}

	bh = (struct bondnlbhdr*)skb->data;
	flag = (bh->local_seq & (1<<31)) >> 31;
	ret = bh->local_seq;
	if(flag == 1) ret -= (1<<31);
	return ret;
}

void bond_nlb_peek_header(struct bonding *bond, struct sk_buff *skb, int *backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr) {
	struct bondnlbhdr *bh = (struct bondnlbhdr*)skb->data;
	u32 flag = (1 << 31);

	*global_seq_ptr = bh->global_seq;
	flag = flag & bh->local_seq;
	flag = flag >> 31;
	*local_seq_ptr = bh->local_seq;
	if(flag == 1) *local_seq_ptr -= (1 << 31);
	*backtoback = flag;
}

void bond_nlb_detach_header(struct bonding *bond, struct sk_buff *skb, int *backtoback, u32 *global_seq_ptr, u32 *local_seq_ptr) {

	struct bondnlbhdr *bh;
	u32 flag = (1 << 31);
	
	bh = (struct bondnlbhdr*)skb->data;
	skb_pull_inline(skb, BOND_NLB_HLEN);
	skb_reset_network_header(skb);
	skb->protocol = bh->protocol;
	skb->csum_start -= BOND_NLB_HLEN;

	*global_seq_ptr = bh->global_seq;
	flag = flag & bh->local_seq;
	flag = flag >> 31;
	*local_seq_ptr = bh->local_seq;
	if(flag == 1) *local_seq_ptr -= (1 << 31);
	*backtoback = flag;
}

void bond_debug_packet_hex(struct sk_buff *skb) {

	unsigned i;
	unsigned char *p;
	
	printk("-------------------------------");
	for(i=0; i<skb->len; i++) {
		if(i % 10 == 0) printk("\n");	
		p = skb->data + i;	
		printk(" %02x", (unsigned int)*p);
	}
	printk("\n");
	printk("-------------------------------\n");
}

// timer handler ---------------------------------------------------------------
void bond_nlb_timeout_handler(struct work_struct *work) {

	struct nlb_neighbor_info *ni = container_of(work, struct nlb_neighbor_info, nlb_timeout_work.work);
	printk("BOND_NLB_TIMEOUT_HANDLER CALLED\n");
	bond_nlb_process_queue(ni->bond, ni, true);
}

void bond_nlb_check_handler(struct work_struct *work) {

	struct bonding *bond = container_of(work, struct bonding, nlb_check_work.work);
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	struct nlb_neighbor_info *n;
	int i;
	int updated, valid;
	u32 delay_average[NLB_MAX_SLAVES];
	u32 packet_schedule[NLB_MAX_SLAVES];
	int max_slave;
	u32 max_delay;
	u32 tmp;

	list_for_each_entry(n, &info->neighbor_list, list) {

		for(i=0; i<slave_cnt; i++) {
			packet_schedule[i] = 0;
		}

		// obtain delay_average
		spin_lock_bh(&info->nlb_lock);
		for(i=0; i<slave_cnt; i++) {
			if(n->rx_gap_count[i] < BOND_NLB_UPDATE_THRESH) delay_average[i] = 0;
			else delay_average[i] = n->rx_gap_total[i] / n->rx_gap_count[i];
		}
		spin_unlock_bh(&info->nlb_lock);

		//----------------------------------------------------------------------
		// decide packet ratio
		max_slave = 0;
		max_delay = delay_average[0];
			
		for(i=1; i<slave_cnt; i++) {
			if(delay_average[i] > max_delay) {
				max_delay = delay_average[i];
				max_slave = i;
			}
		}

		if(max_delay > 0) packet_schedule[max_slave] = 2;

		for(i=0; i<slave_cnt; i++) {
			if(i == max_slave) continue;
			if(delay_average[i] == 0) continue;

			tmp = max_delay * 20 / delay_average[i] + 5;
			tmp = tmp / 10;

			packet_schedule[i] = tmp;
		}

		//--------------------------------------------------------------------------------------------------------------
		// all slaves should have more than BOND_NLB_UPDATE_THRESH packets to update the schedule.
		valid = 1;
		for(i=0; i<slave_cnt; i++) {
			if(packet_schedule[i] == 0) {
				valid = 0;
				break;
			}
		}	
			
		if(valid == 0) {
			for(i=0; i<slave_cnt; i++) {
				packet_schedule[i] = 0;
			}
		}
		//--------------------------------------------------------------------------------------------------------------
	
		if(n->param_auto_schedule == 1) {
			updated = 0;
			spin_lock_bh(&info->nlb_lock);
			//printk("For neighbor %pM\n", &n->addr);
			for(i=0; i<slave_cnt; i++) {
				//printk("slave %d average: %6u count: %6u sched(old): %2u sched(new): %2u\n", i, delay_average[i], n->rx_gap_count[i], n->rx_schedule[i], packet_schedule[i]);
				if(packet_schedule[i] > 0 && n->rx_schedule[i] != packet_schedule[i]) {
					n->rx_schedule[i] = packet_schedule[i];
					updated = 1;
				}
			}		
			//printk("\n");
			spin_unlock_bh(&info->nlb_lock);

			if(updated) bond_nlb_send_control(bond, n);
		}
		
		spin_lock_bh(&info->nlb_lock);
		// reset statistics
		for(i=0; i<slave_cnt; i++) {
			n->rx_gap_total[i] = 0;
			n->rx_gap_count[i] = 0;
		}
		spin_unlock_bh(&info->nlb_lock);
	}

	queue_delayed_work(bond->wq, &bond->nlb_check_work, msecs_to_jiffies(BOND_NLB_CHECK_INTERVAL));	// 3 seconds
}

void bond_nlb_hello_handler(struct work_struct *work) {

	struct bonding *bond = container_of(work, struct bonding, nlb_hello_work.work);

	//--------------------------------------------------------------------------
	// generate a hello packet
	struct sk_buff *skb;
	struct hello_marker_header *hello_header;
	int length = sizeof(struct hello_marker_header);

	// create a socket buffer
	skb = dev_alloc_skb(length + BOND_NLB_HLEN);
	if(!skb) return;

	// assign socket buffer variables
	skb_reset_mac_header(skb);
	skb->network_header = skb->mac_header + ETH_HLEN;
	skb->protocol = PKT_TYPE_BOND_HELLO;			
	skb->priority = TC_PRIO_CONTROL;
	skb->dev = bond->dev;

	// fill in the hello_marker_header
	hello_header = (struct hello_marker_header*)skb_put(skb, length);
	memcpy(hello_header->hdr.h_dest, mac_bcast, ETH_ALEN);
	memcpy(hello_header->hdr.h_source, bond->dev->dev_addr, ETH_ALEN);
	hello_header->hdr.h_proto = PKT_TYPE_BOND_HELLO;
	memcpy(hello_header->marker.addr, bond->dev->dev_addr, ETH_ALEN);
	
	// send over the first interface (TEMPORARY)
	bond_xmit_nlb_slave_id(bond, skb, 0);
	//--------------------------------------------------------------------------

	queue_delayed_work(bond->wq, &bond->nlb_hello_work, msecs_to_jiffies(BOND_NLB_HELLO_INTERVAL));
}

void bond_nlb_send_control(struct bonding *bond, struct nlb_neighbor_info *ni) {

	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);

	//--------------------------------------------------------------------------
	// generate a control packet
	struct sk_buff *skb;
	struct control_marker_header *control_header;
	int length = sizeof(struct control_marker_header);
	int i;

	//printk("SEND_CONTROL\n");

	// create a socket buffer
	skb = dev_alloc_skb(length + BOND_NLB_HLEN);
	if(!skb) return;

	// assign socket buffer variables
	skb_reset_mac_header(skb);
	skb->network_header = skb->mac_header + ETH_HLEN;
	skb->protocol = PKT_TYPE_BOND_CONTROL;
	skb->priority = TC_PRIO_CONTROL;
	skb->dev = bond->dev;

	// fill in the control_marker_header
	control_header = (struct control_marker_header*)skb_put(skb, length);
	memcpy(control_header->hdr.h_dest, ni->addr, ETH_ALEN);
	memcpy(control_header->hdr.h_source, bond->dev->dev_addr, ETH_ALEN);
	control_header->hdr.h_proto = PKT_TYPE_BOND_CONTROL;
	memcpy(control_header->marker.addr, bond->dev->dev_addr, ETH_ALEN);
	//for(i=0; i<NLB_MAX_SLAVES; i++) control_header->marker.schedule[i] = 0;
	for(i=0; i<slave_cnt; i++) {
		control_header->marker.schedule[i] = ni->rx_schedule[i];
	}

	// send over the first interface (TEMPORARY)
	bond_xmit_nlb_slave_id(bond, skb, 0);
}

bool bond_nlb_skb_timeout(struct sk_buff *skb) {

	struct timeval tv_diff;
	ktime_t now, diff;
	u32 diff_usec;

	struct timeval tv_rx, tv_now;

	// assumption: this skb has received time marked in tstamp
	now = ktime_get();
	diff = ktime_sub(now, skb->tstamp);
	tv_diff = ktime_to_timeval(diff);

	diff_usec = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
	if(diff_usec >= BOND_NLB_HOLD_TIME - 100) {		// margin: 100 usecs
		tv_rx = ktime_to_timeval(skb->tstamp);
		tv_now = ktime_to_timeval(now);
		//printk("PACKET TIMEOUT\n");
		return true;	
	}
	
	return false;
}

u32 bond_nlb_skb_timeout_left(struct sk_buff *skb) {

	ktime_t elapsed;
	struct timeval tv_elapsed;
	u32 u32_elapsed;
	
	elapsed = ktime_sub(ktime_get(), skb->tstamp);
	tv_elapsed = ktime_to_timeval(elapsed);
	u32_elapsed = tv_elapsed.tv_sec * 1000000 + tv_elapsed.tv_usec;
		
	return BOND_NLB_HOLD_TIME - u32_elapsed;
}

