#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/netdevice.h>

#include "bonding.h"
#include "bond_alb.h"
// jungmin ---------------------------------------------------------------------
#include "bond_nlb.h"
//------------------------------------------------------------------------------

#if defined(CONFIG_DEBUG_FS) && !defined(CONFIG_NET_NS)

#include <linux/debugfs.h>
#include <linux/seq_file.h>

static struct dentry *bonding_debug_root;

/* Show RLB hash table */
static int bond_debug_rlb_hash_show(struct seq_file *m, void *v)
{
	struct bonding *bond = m->private;
	struct alb_bond_info *bond_info = &(BOND_ALB_INFO(bond));
	struct rlb_client_info *client_info;
	u32 hash_index;

	if (BOND_MODE(bond) != BOND_MODE_ALB)
		return 0;

	seq_printf(m, "SourceIP        DestinationIP   "
			"Destination MAC   DEV\n");

	spin_lock_bh(&bond->mode_lock);

	hash_index = bond_info->rx_hashtbl_used_head;
	for (; hash_index != RLB_NULL_INDEX;
	     hash_index = client_info->used_next) {
		client_info = &(bond_info->rx_hashtbl[hash_index]);
		seq_printf(m, "%-15pI4 %-15pI4 %-17pM %s\n",
			&client_info->ip_src,
			&client_info->ip_dst,
			&client_info->mac_dst,
			client_info->slave->dev->name);
	}

	spin_unlock_bh(&bond->mode_lock);

	return 0;
}

static int bond_debug_rlb_hash_open(struct inode *inode, struct file *file)
{
	return single_open(file, bond_debug_rlb_hash_show, inode->i_private);
}

static const struct file_operations bond_debug_rlb_hash_fops = {
	.owner		= THIS_MODULE,
	.open		= bond_debug_rlb_hash_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

// jungmin ---------------------------------------------------------------------
static ssize_t read_file_nlb(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
	
	struct bonding *bond = file->private_data;
	unsigned int len = 0, size = 4194304;	// careful about the size (device memory should stand it)
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	int i, j;
	char *buf;
	struct list_head *iter;
	struct slave *slave;
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	ssize_t retval = 0;
	u32 c, total; 
	struct timespec tv;
	
	// 1. allocate memory to buf
	buf = kzalloc(size, GFP_KERNEL);
	if(buf == NULL) return -ENOMEM;

	spin_lock_bh(&info->nlb_lock);

	// 2. print out packet schedule and tx/rx counters
	i = slave_cnt;
	j = 0;
	bond_for_each_slave_rcu(bond, slave, iter) {
        len += scnprintf(buf+len, size-len, "TX[%s]: %6lu  RX[%s]: %6lu  pkts[%s]: %3lu\n",
            slave->dev->name, (long unsigned)info->tx_counter[j],
            slave->dev->name, (long unsigned)info->rx_counter[j],
            slave->dev->name, (long unsigned)info->pkts_slave[j]);
        j++;

        if(--i < 0) break;
    }

	// 3. print statistics -----------------------------------------------------
	c = 0;
	for(i=0; i<slave_cnt; i++) c += info->tx_counter[i] + info->rx_counter[i];
	total = c;

	if(c > NLB_REPORT_COUNT) c = NLB_REPORT_COUNT;
	for(i=0; i<c; i++) {
		tv = ktime_to_timespec(info->tstamp[i]);
        len += scnprintf(buf+len, size-len, " %5d ", i);
        len += scnprintf(buf+len, size-len, "%10lu.%09lu ", tv.tv_sec, tv.tv_nsec);
        len += scnprintf(buf+len, size-len, "<%u> ", (unsigned)info->interface[i]);
        if(info->txrx[i] == ACTION_TYPE_TX) len += scnprintf(buf+len, size-len, "TX ");
        else if(info->txrx[i] == ACTION_TYPE_RX) len += scnprintf(buf+len, size-len, "RX ");
        else if(info->txrx[i] == ACTION_TYPE_ACCEPT) len += scnprintf(buf+len, size-len, "AC ");
        len += scnprintf(buf+len, size-len, "%4lu ", (long unsigned)info->len[i]);
        len += scnprintf(buf+len, size-len, "%5lu ", (long unsigned)info->tcpsport[i]);      
        len += scnprintf(buf+len, size-len, "%5lu ", (long unsigned)info->tcpdport[i]);      
        len += scnprintf(buf+len, size-len, "%10lu ", (long unsigned)info->tcpseqnum[i]);
        len += scnprintf(buf+len, size-len, "%10lu ", (long unsigned)info->tcpacknum[i]);
        len += scnprintf(buf+len, size-len, "%10lu ", (long unsigned)info->bondglobalseq[i]);
        len += scnprintf(buf+len, size-len, "%10lu ", (long unsigned)info->bondlocalseq[i]);
        len += scnprintf(buf+len, size-len, "%lu ", (long unsigned)info->backtoback[i]);
        if(info->protocol[i] == IPPROTO_TCP) len += scnprintf(buf+len, size-len, "TCP ");
        else len += scnprintf(buf+len, size-len, "UDP ");
        len += scnprintf(buf+len, size-len, "\n");
	}

	spin_unlock_bh(&info->nlb_lock);	

	len += scnprintf(buf+len, size-len, "\ntotal number of packets: %lu\n", (long unsigned)total);

	// 5. print out length of the buffer (to see if it exceeds the 'size'.);
	len += scnprintf(buf+len, size-len, "\nlen: %10u\n", len);
	
	if(len > size) len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return retval;
}

static ssize_t write_file_nlb(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {

	struct bonding *bond = file->private_data;
	unsigned long iv;	// input value
	char buf[32];
	ssize_t len;
	int i, j, pkts_sum;
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));

	// 1. get the user input
	len = min(count, sizeof(buf)-1);
	if(copy_from_user(buf, user_buf, len)) return -EFAULT;
	buf[len] = '\0';
	if(kstrtoul(buf, 0, &iv)) return -EINVAL;

	// 2. set packet schedule based on user input
	i = iv / 100;
	j = iv % 100;

	spin_lock_bh(&info->nlb_lock);

	if(i < slave_cnt) info->pkts_slave[i] = j;

	// check if packet schedule is valid (should not be 0)
	pkts_sum = 0;
	for(i=0; i<slave_cnt; i++) pkts_sum += info->pkts_slave[i];
	if(pkts_sum == 0) info->pkts_slave[0] = 1;

	// 3. if the user input is 999, reset all counters
	if(iv == 999) {
		for(i=0; i<slave_cnt; i++) {
            info->tx_counter[i] = 0;
            info->rx_counter[i] = 0;
        }
	}

	spin_unlock_bh(&info->nlb_lock);	
	return count;
}

static const struct file_operations bond_debug_nlb_fops = {
    .read       = read_file_nlb,
    .write      = write_file_nlb,
    .owner      = THIS_MODULE,
    .open       = simple_open,
    .llseek     = default_llseek,
};
//------------------------------------------------------------------------------
void bond_debug_register(struct bonding *bond)
{
	if (!bonding_debug_root)
		return;

	bond->debug_dir =
		debugfs_create_dir(bond->dev->name, bonding_debug_root);

	if (!bond->debug_dir) {
		netdev_warn(bond->dev, "failed to register to debugfs\n");
		return;
	}

	debugfs_create_file("rlb_hash_table", 0400, bond->debug_dir,
				bond, &bond_debug_rlb_hash_fops);

// jungmin ---------------------------------------------------------------------
	debugfs_create_file("nlb_info", S_IRUSR | S_IWUSR, bond->debug_dir, bond, &bond_debug_nlb_fops);
//------------------------------------------------------------------------------
}

void bond_debug_unregister(struct bonding *bond)
{
	if (!bonding_debug_root)
		return;

	debugfs_remove_recursive(bond->debug_dir);
}

void bond_debug_reregister(struct bonding *bond)
{
	struct dentry *d;

	if (!bonding_debug_root)
		return;

	d = debugfs_rename(bonding_debug_root, bond->debug_dir,
			   bonding_debug_root, bond->dev->name);
	if (d) {
		bond->debug_dir = d;
	} else {
		netdev_warn(bond->dev, "failed to reregister, so just unregister old one\n");
		bond_debug_unregister(bond);
	}
}

void bond_create_debugfs(void)
{
	bonding_debug_root = debugfs_create_dir("bonding", NULL);

	if (!bonding_debug_root) {
		pr_warn("Warning: Cannot create bonding directory in debugfs\n");
	}
}

void bond_destroy_debugfs(void)
{
	debugfs_remove_recursive(bonding_debug_root);
	bonding_debug_root = NULL;
}

//------------------------------------------------------------------------------
// debug file system for NLB mode
static ssize_t read_file_nlb_station_stats(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
	struct bonding *bond = ni->bond;
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	unsigned int len = 0, size = 4096;
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	char *buf;
	struct list_head *iter;
	struct slave *slave;
	ssize_t retval = 0;
	int i, j;

	// allocate memory to buf
	buf = kzalloc(size, GFP_KERNEL);
	if(buf == NULL) return -ENOMEM;

	spin_lock_bh(&info->nlb_lock);
	
	i = slave_cnt;
	j = 0;
	bond_for_each_slave_rcu(bond, slave, iter) {
		len += scnprintf(buf+len, size-len, "SLAVE [%s] - SCHED: %u  TX: %6u  RX: %6u\n", slave->dev->name, ni->tx_schedule[j], ni->tx_counter[j], ni->rx_counter[j]);
		j++;
		if(--i<0) break;
	}

	spin_unlock_bh(&info->nlb_lock);

	if(len > size) len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return retval;
}

static ssize_t write_file_nlb_station_stats(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
	struct bonding *bond = ni->bond;
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	char buf[32];
	ssize_t len;
	int i, j, k, pkts_sum, prev;
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
	unsigned long iv;

	// get user input
	len = min(count, sizeof(buf)-1);
	if(copy_from_user(buf, user_buf, len)) return -EFAULT;
	buf[len] = '\0';
	if(kstrtoul(buf, 0, &iv)) return -EINVAL;

	i = iv / 100;
	j = iv % 100;

	spin_lock_bh(&info->nlb_lock);
	
	if(i < slave_cnt) {
		prev = ni->tx_schedule[i];
		ni->tx_schedule[i] = j;
	}
	
	// check to see if packet schedule is 0 for every interface
	pkts_sum = 0;
	for(k=0; k<slave_cnt; k++) pkts_sum += ni->tx_schedule[k];
	if(pkts_sum == 0) {
		printk("WARNING: command not executed because every interface is scheduled zero packets.\n");
		ni->tx_schedule[i] = prev;	// revert
	}

	// if the user input is 999, reset all counters
	if(iv == 999) {
		for(i=0; i<slave_cnt; i++) {
            ni->tx_counter[i] = 0;
            ni->rx_counter[i] = 0;
        }
	}

	spin_unlock_bh(&info->nlb_lock);
	return count;
}

static const struct file_operations bond_debug_nlb_station_stats_fops = {
    .read       = read_file_nlb_station_stats,
    .write      = write_file_nlb_station_stats,
    .owner      = THIS_MODULE,
    .open       = simple_open,
    .llseek     = default_llseek,
};

static ssize_t read_file_nlb_station_auto_schedule(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
	struct bonding *bond = ni->bond;
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	unsigned int len = 0, size = 4096;
	char *buf;
	ssize_t retval = 0;

	// allocate memory to buf
	buf = kzalloc(size, GFP_KERNEL);
	if(buf == NULL) return -ENOMEM;

	spin_lock_bh(&info->nlb_lock);
	len += scnprintf(buf+len, size-len, "%u\n", ni->param_auto_schedule);
	spin_unlock_bh(&info->nlb_lock);

	if(len > size) len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return retval;
}

static ssize_t write_file_nlb_station_auto_schedule(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
    struct bonding *bond = ni->bond;
    struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
    char buf[32];
    ssize_t len;
    unsigned long iv;

	// get user input
    len = min(count, sizeof(buf)-1);
    if(copy_from_user(buf, user_buf, len)) return -EFAULT;
    buf[len] = '\0';
    if(kstrtoul(buf, 0, &iv)) return -EINVAL;

	spin_lock_bh(&info->nlb_lock);

	if(iv == 0) ni->param_auto_schedule = 0;
	else if(iv == 1) ni->param_auto_schedule = 1;

	spin_unlock_bh(&info->nlb_lock);

	return count;
}

static const struct file_operations bond_debug_nlb_station_auto_schedule_fops = {
    .read       = read_file_nlb_station_auto_schedule,
    .write      = write_file_nlb_station_auto_schedule,
    .owner      = THIS_MODULE,
    .open       = simple_open,
    .llseek     = default_llseek,
};

static ssize_t read_file_nlb_station_inorder_delivery(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
	struct bonding *bond = ni->bond;
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	unsigned int len = 0, size = 4096;
	char *buf;
	ssize_t retval = 0;

	// allocate memory to buf
	buf = kzalloc(size, GFP_KERNEL);
	if(buf == NULL) return -ENOMEM;

	spin_lock_bh(&info->nlb_lock);
	len += scnprintf(buf+len, size-len, "%u\n", ni->param_inorder_delivery);
	spin_unlock_bh(&info->nlb_lock);

	if(len > size) len = size;
	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return retval;
}

static ssize_t write_file_nlb_station_inorder_delivery(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {

	struct nlb_neighbor_info *ni = file->private_data;
    struct bonding *bond = ni->bond;
    struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	int slave_cnt = ACCESS_ONCE(bond->slave_cnt);
    char buf[32];
    ssize_t len;
    unsigned long iv;
	int i;

	// get user input
    len = min(count, sizeof(buf)-1);
    if(copy_from_user(buf, user_buf, len)) return -EFAULT;
    buf[len] = '\0';
    if(kstrtoul(buf, 0, &iv)) return -EINVAL;

	spin_lock_bh(&info->nlb_lock);

	if(iv == 0) {
		// important: flush receive queue and cancel timeout timer
		if(ni->param_inorder_delivery == 1)  {
			bond_nlb_accept_packets_immediately(bond, ni);
			cancel_delayed_work(&ni->nlb_timeout_work);
		}
		ni->param_inorder_delivery = 0;
	}
	else if(iv == 1) ni->param_inorder_delivery = 1;

	spin_unlock_bh(&info->nlb_lock);

	return count;
}

static const struct file_operations bond_debug_nlb_station_inorder_delivery_fops = {
    .read       = read_file_nlb_station_inorder_delivery,
    .write      = write_file_nlb_station_inorder_delivery,
    .owner      = THIS_MODULE,
    .open       = simple_open,
    .llseek     = default_llseek,
};

void bond_debug_nlb_create_dir(struct bonding *bond) {
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	info->nlb_station_debug_dir = debugfs_create_dir("stations", bond->debug_dir);
}

void bond_debug_nlb_create_station_dir(struct bonding *bond, struct nlb_neighbor_info *ni) {
	struct nlb_bond_info *info = &(BOND_NLB_INFO(bond));
	u8 mac[3*ETH_ALEN];
	snprintf(mac, sizeof(mac), "%pM", &ni->addr);
	ni->nlb_debug_dir = debugfs_create_dir(mac, info->nlb_station_debug_dir);
}

void bond_debug_nlb_create_station_files(struct bonding *bond, struct nlb_neighbor_info *ni) {
	debugfs_create_file("stats", S_IRUSR | S_IWUSR, ni->nlb_debug_dir, ni, &bond_debug_nlb_station_stats_fops);	
	debugfs_create_file("auto_schedule", S_IRUSR | S_IWUSR, ni->nlb_debug_dir, ni, &bond_debug_nlb_station_auto_schedule_fops);
	debugfs_create_file("inorder_delivery", S_IRUSR | S_IWUSR, ni->nlb_debug_dir, ni, &bond_debug_nlb_station_inorder_delivery_fops);
}


//TODO
//------------------------------------------------------------------------------

#else /* !CONFIG_DEBUG_FS */

void bond_debug_register(struct bonding *bond)
{
}

void bond_debug_unregister(struct bonding *bond)
{
}

void bond_debug_reregister(struct bonding *bond)
{
}

void bond_create_debugfs(void)
{
}

void bond_destroy_debugfs(void)
{
}

#endif /* CONFIG_DEBUG_FS */
