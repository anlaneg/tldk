/*
 * Copyright (c) 2016  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PORT_H_
#define PORT_H_

static void
prepare_hash_key(struct netbe_port *uprt, uint8_t key_size, uint16_t family)
{
	uint32_t align_nb_q;

	/*将负责此port的核对齐成2的幂*/
	align_nb_q = rte_align32pow2(uprt->nb_lcore);
	memset(uprt->hash_key, 0, RSS_HASH_KEY_LENGTH);/*全清0*/
	uprt->hash_key_size = key_size;
	/*在特别的位置填充对齐的q*/
	if (family == AF_INET)
		uprt->hash_key[RSS_HASH_KEY_DEST_PORT_LOC_IPV4] = align_nb_q;
	else
		uprt->hash_key[RSS_HASH_KEY_DEST_PORT_LOC_IPV6] = align_nb_q;
}

static int
update_rss_conf(struct netbe_port *uprt,
	const struct rte_eth_dev_info *dev_info,
	struct rte_eth_conf *port_conf, uint32_t proto)
{
	uint8_t hash_key_size;

	if (uprt->nb_lcore > 1) {
	    /*负责此port的cpu数超过1*/
		if (dev_info->hash_key_size > 0)
			hash_key_size = dev_info->hash_key_size;
		else {
			RTE_LOG(ERR, USER1,
				"%s: dev_info did not provide a valid hash "
				"key size\n", __func__);
			return -EINVAL;
		}

		if (uprt->ipv4 != INADDR_ANY &&
				memcmp(&uprt->ipv6, &in6addr_any,
				sizeof(uprt->ipv6)) != 0) {
		    /*按口同时使能ipv4,ipv6*/
			RTE_LOG(ERR, USER1,
				"%s: RSS for both IPv4 and IPv6 not "
				"supported!\n", __func__);
			return -EINVAL;
		} else if (uprt->ipv4 != INADDR_ANY) {
		    /*填充ipv4 hash key*/
			prepare_hash_key(uprt, hash_key_size, AF_INET);
		} else if (memcmp(&uprt->ipv6, &in6addr_any, sizeof(uprt->ipv6))
				!= 0) {
		    /*填充ipv6 hash key*/
			prepare_hash_key(uprt, hash_key_size, AF_INET6);
		} else {
			RTE_LOG(ERR, USER1,
				"%s: No IPv4 or IPv6 address is found!\n",
				__func__);
			return -EINVAL;
		}

		/*采用特别的rss hash，按目的port进行分发*/
		port_conf->rxmode.mq_mode = ETH_MQ_RX_RSS;
		if (proto == TLE_PROTO_TCP)
			port_conf->rx_adv_conf.rss_conf.rss_hf = ETH_RSS_TCP;
		else
			port_conf->rx_adv_conf.rss_conf.rss_hf = ETH_RSS_UDP;
		port_conf->rx_adv_conf.rss_conf.rss_key_len = hash_key_size;
		port_conf->rx_adv_conf.rss_conf.rss_key = uprt->hash_key;
	}

	return 0;
}

static uint32_t
qidx_from_hash_index(uint32_t hash, uint32_t align_nb_q)
{
	uint32_t i, nb_bit, q;

	nb_bit = (sizeof(uint32_t) * CHAR_BIT) - __builtin_clz(align_nb_q - 1);
	q = (hash & 1);
	for (i = 1; i < nb_bit; i++) {
		hash >>= 1;
		q <<= 1;
		q |= (hash & 1);
	}

	return q;
}

static int
update_rss_reta(struct netbe_port *uprt,
	const struct rte_eth_dev_info *dev_info)
{
	struct rte_eth_rss_reta_entry64 reta_conf[RSS_RETA_CONF_ARRAY_SIZE];
	int32_t i, rc, align_nb_q;
	int32_t q_index, idx, shift;

	if (uprt->nb_lcore > 1) {
		if (dev_info->reta_size == 0) {
			RTE_LOG(ERR, USER1,
				"%s: Redirection table size 0 is invalid for "
				"RSS\n", __func__);
			return -EINVAL;
		}
		RTE_LOG(NOTICE, USER1,
			"%s: The reta size of port %d is %u\n",
			__func__, uprt->id, dev_info->reta_size);

		if (dev_info->reta_size > ETH_RSS_RETA_SIZE_512) {
			RTE_LOG(ERR, USER1,
				"%s: More than %u entries of Reta not supported\n",
				__func__, ETH_RSS_RETA_SIZE_512);
			return -EINVAL;
		}

		memset(reta_conf, 0, sizeof(reta_conf));
		align_nb_q = rte_align32pow2(uprt->nb_lcore);
		for (i = 0; i < align_nb_q; i++) {
			q_index = qidx_from_hash_index(i, align_nb_q) %
						uprt->nb_lcore;

			idx = i / RTE_RETA_GROUP_SIZE;
			shift = i % RTE_RETA_GROUP_SIZE;
			reta_conf[idx].mask |= (1ULL << shift);
			reta_conf[idx].reta[shift] = q_index;
			RTE_LOG(NOTICE, USER1,
				"%s: port=%u RSS reta conf: hash=%u, q=%u\n",
				__func__, uprt->id, i, q_index);
		}

		rc = rte_eth_dev_rss_reta_update(uprt->id,
				reta_conf, dev_info->reta_size);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: Bad redirection table parameter, "
				"rc = %d\n", __func__, rc);
			return rc;
		}
	}

	return 0;
}

/*
 * Initilise DPDK port.
 * In current version, multi-queue per port is used.
 */
static int
port_init(struct netbe_port *uprt, uint32_t proto)
{
	int32_t rc;
	struct rte_eth_conf port_conf;
	struct rte_eth_dev_info dev_info;

	/*取指定port的dev infor*/
	rte_eth_dev_info_get(uprt->id, &dev_info);
	if ((dev_info.rx_offload_capa & uprt->rx_offload) != uprt->rx_offload) {
	    /*遇到设备不支持的rx offload能力，报错*/
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested RX offloads don't match, "
			"supported: %#" PRIx64 ", requested: %#" PRIx64 ";\n",
			uprt->id, (uint64_t)dev_info.rx_offload_capa,
			(uint64_t)uprt->rx_offload);
		return -EINVAL;
	}
	if ((dev_info.tx_offload_capa & uprt->tx_offload) != uprt->tx_offload) {
	    /*遇到设备不支持的tx offload能力，报错*/
		RTE_LOG(ERR, USER1,
			"port#%u supported/requested TX offloads don't match, "
			"supported: %#" PRIx64 ", requested: %#" PRIx64 ";\n",
			uprt->id, (uint64_t)dev_info.tx_offload_capa,
			(uint64_t)uprt->tx_offload);
		return -EINVAL;
	}

	port_conf = port_conf_default;
	if ((uprt->rx_offload & RX_CSUM_OFFLOAD) != 0) {
	    /*rx方向开启check sum offload能力*/
		RTE_LOG(ERR, USER1, "%s(%u): enabling RX csum offload;\n",
			__func__, uprt->id);
		port_conf.rxmode.offloads |= uprt->rx_offload & RX_CSUM_OFFLOAD;
	}
	/*指明rx方向容许的最大packet长度*/
	port_conf.rxmode.max_rx_pkt_len = uprt->mtu + RTE_ETHER_CRC_LEN;
	/*超时1518，指明使能jumbo能力*/
	if (port_conf.rxmode.max_rx_pkt_len > RTE_ETHER_MAX_LEN)
		port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;

	/*更新rss hash，以便按dst port进行分发*/
	rc = update_rss_conf(uprt, &dev_info, &port_conf, proto);
	if (rc != 0)
		return rc;

	/*指明tx方向offload能力*/
	port_conf.txmode.offloads = uprt->tx_offload;

	/*配置此接口，rx与Tx相同，菜uprt->nb_lcore个*/
	rc = rte_eth_dev_configure(uprt->id, uprt->nb_lcore, uprt->nb_lcore,
			&port_conf);
	RTE_LOG(NOTICE, USER1,
		"%s: rte_eth_dev_configure(prt_id=%u, nb_rxq=%u, nb_txq=%u) "
		"returns %d;\n", __func__, uprt->id, uprt->nb_lcore,
		uprt->nb_lcore, rc);
	if (rc != 0)
		return rc;

	return 0;
}

/*利用mp初始化uprt端口的rx,tx队列*/
static int
queue_init(struct netbe_port *uprt, struct rte_mempool *mp)
{
	int32_t socket, rc;
	uint16_t q;
	uint32_t nb_rxd, nb_txd;
	struct rte_eth_dev_info dev_info;

	/*取port信息*/
	rte_eth_dev_info_get(uprt->id, &dev_info);

	/*取设备对应的socket*/
	socket = rte_eth_dev_socket_id(uprt->id);

	dev_info.default_rxconf.rx_drop_en = 1;

	/*rx,tx的描述符数目*/
	nb_rxd = RTE_MIN(RX_RING_SIZE, dev_info.rx_desc_lim.nb_max);
	nb_txd = RTE_MIN(TX_RING_SIZE, dev_info.tx_desc_lim.nb_max);

	dev_info.default_txconf.tx_free_thresh = nb_txd / 2;

	/*由于有nb_lcore负责此port，故rx队列有nb_lcore个，这里进行初始化*/
	for (q = 0; q < uprt->nb_lcore; q++) {
		rc = rte_eth_rx_queue_setup(uprt->id, q, nb_rxd/*rx描述符数量*/,
			socket, &dev_info.default_rxconf, mp);
		if (rc < 0) {
			RTE_LOG(ERR, USER1,
				"%s: rx queue=%u setup failed with error "
				"code: %d\n", __func__, q, rc);
			return rc;
		}
	}

	/*tx队列初始化*/
	for (q = 0; q < uprt->nb_lcore; q++) {
		rc = rte_eth_tx_queue_setup(uprt->id, q, nb_txd,
			socket, &dev_info.default_txconf);
		if (rc < 0) {
			RTE_LOG(ERR, USER1,
				"%s: tx queue=%u setup failed with error "
				"code: %d\n", __func__, q, rc);
			return rc;
		}
	}
	return 0;
}

/*
 * Check that lcore is enabled, not master, and not in use already.
 */
static int
check_lcore(uint32_t lc)
{
    /*检查此core是否被启用*/
	if (rte_lcore_is_enabled(lc) == 0) {
		RTE_LOG(ERR, USER1, "lcore %u is not enabled\n", lc);
		return -EINVAL;
	}

	/*检查此core是否已被占用*/
	if (rte_eal_get_lcore_state(lc) == RUNNING) {
		RTE_LOG(ERR, USER1, "lcore %u already in use\n", lc);
		return -EINVAL;
	}
	return 0;
}

static void
log_netbe_prt(const struct netbe_port *uprt)
{
	uint32_t i;
	char corelist[2 * RTE_MAX_LCORE + 1];
	char hashkey[2 * RSS_HASH_KEY_LENGTH];

	memset(corelist, 0, sizeof(corelist));
	memset(hashkey, 0, sizeof(hashkey));
	for (i = 0; i < uprt->nb_lcore; i++)
		if (i < uprt->nb_lcore - 1)
			sprintf(corelist + (2 * i), "%u,", uprt->lcore_id[i]);
		else
			sprintf(corelist + (2 * i), "%u", uprt->lcore_id[i]);

	for (i = 0; i < uprt->hash_key_size; i++)
		sprintf(hashkey + (2 * i), "%02x", uprt->hash_key[i]);

	RTE_LOG(NOTICE, USER1,
		"uprt %p = <id = %u, lcore = <%s>, mtu = %u, "
		"rx_offload = %#" PRIx64 ", tx_offload = %#" PRIx64 ",\n"
		"ipv4 = %#x, "
		"ipv6 = %04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx, "
		"mac = %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx>;\n"
		"hashkey = %s;\n",
		uprt, uprt->id, corelist,
		uprt->mtu, uprt->rx_offload, uprt->tx_offload,
		uprt->ipv4,
		uprt->ipv6.s6_addr16[0], uprt->ipv6.s6_addr16[1],
		uprt->ipv6.s6_addr16[2], uprt->ipv6.s6_addr16[3],
		uprt->ipv6.s6_addr16[4], uprt->ipv6.s6_addr16[5],
		uprt->ipv6.s6_addr16[6], uprt->ipv6.s6_addr16[7],
		uprt->mac.addr_bytes[0], uprt->mac.addr_bytes[1],
		uprt->mac.addr_bytes[2], uprt->mac.addr_bytes[3],
		uprt->mac.addr_bytes[4], uprt->mac.addr_bytes[5],
		hashkey);
}

static void
log_netbe_cfg(const struct netbe_cfg *ucfg)
{
	uint32_t i;

	RTE_LOG(NOTICE, USER1,
		"ucfg @ %p, prt_num = %u\n", ucfg, ucfg->prt_num);

	for (i = 0; i != ucfg->prt_num; i++)
		log_netbe_prt(ucfg->prt + i);
}

static int
pool_init(uint32_t sid, uint32_t mpool_buf_num)
{
	int32_t rc;
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	snprintf(name, sizeof(name), "MP%u", sid);
	mp = rte_pktmbuf_pool_create(name, mpool_buf_num, MPOOL_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, sid - 1);
	if (mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n",
			__func__, sid - 1, rc);
		return rc;
	}

	mpool[sid] = mp;
	return 0;
}

static int
frag_pool_init(uint32_t sid, uint32_t mpool_buf_num)
{
	int32_t rc;
	struct rte_mempool *frag_mp;
	char frag_name[RTE_MEMPOOL_NAMESIZE];

	snprintf(frag_name, sizeof(frag_name), "frag_MP%u", sid);
	frag_mp = rte_pktmbuf_pool_create(frag_name, mpool_buf_num,
		MPOOL_CACHE_SIZE, 0, FRAG_MBUF_BUF_SIZE, sid - 1);
	if (frag_mp == NULL) {
		rc = -rte_errno;
		RTE_LOG(ERR, USER1, "%s(%d) failed with error code: %d\n",
			__func__, sid - 1, rc);
		return rc;
	}

	frag_mpool[sid] = frag_mp;
	return 0;
}

/*取指定logic core对应的netbe_lcore结构*/
static struct netbe_lcore *
find_initilized_lcore(struct netbe_cfg *cfg, uint32_t lc_num)
{
	uint32_t i;

	for (i = 0; i < cfg->cpu_num; i++)
		if (cfg->cpu[i].id == lc_num)
			return &cfg->cpu[i];

	return NULL;
}

/*
 * Setup all enabled ports.
 */
static int
netbe_port_init(struct netbe_cfg *cfg)
{
	int32_t rc;
	uint32_t i, sid, j;
	struct netbe_port *prt;
	struct netbe_lcore *lc;

	//遍历所有的端口
	for (i = 0; i != cfg->prt_num; i++) {
		prt = cfg->prt + i;
		//配置接口rx,tx,配置rss
		rc = port_init(prt, cfg->proto);
		if (rc != 0) {
			RTE_LOG(ERR, USER1,
				"%s: port=%u init failed with error code: %d\n",
				__func__, prt->id, rc);
			return rc;
		}

		/*取接口mac地址*/
		rte_eth_macaddr_get(prt->id, &prt->mac);

		if (cfg->promisc)
			//设置混杂模式
			rte_eth_promiscuous_enable(prt->id);

		/*遍历负责此port的所有core*/
		for (j = 0; j < prt->nb_lcore; j++) {
		    /*检查此core是否可用*/
			rc = check_lcore(prt->lcore_id[j]);
			if (rc != 0) {
				RTE_LOG(ERR, USER1,
					"%s: processing failed with err: %d\n",
					__func__, rc);
				return rc;
			}

			/*除socket id,使其从1开始编号*/
			sid = rte_lcore_to_socket_id(prt->lcore_id[j]) + 1;
			assert(sid < RTE_DIM(mpool));

			if (mpool[sid] == NULL) {
			    /*初始化此sid对应的mbuf pool*/
				rc = pool_init(sid, cfg->mpool_buf_num);
				if (rc != 0)
					return rc;
			}

			if (frag_mpool[sid] == NULL) {
			    /*初始化sid上的frag pool*/
				rc = frag_pool_init(sid, cfg->mpool_buf_num);
				if (rc != 0)
					return rc;
			}

			//利用此socket对应的pool初始化port队列
			rc = queue_init(prt, mpool[sid]);
			if (rc != 0) {
				RTE_LOG(ERR, USER1,
					"%s: lcore=%u queue init failed with "
					"err: %d\n",
					__func__, prt->lcore_id[j], rc);
				return rc;
			}

			/* calculate number of queues and assign queue id
			 * per lcore. */
			lc = find_initilized_lcore(cfg, prt->lcore_id[j]);
			if (lc == NULL) {
			    /*首次填充此lc,分配一个空间，并填充*/
				lc = &cfg->cpu[cfg->cpu_num];
				lc->id = prt->lcore_id[j];
				lc->proto = becfg.proto;
				cfg->cpu_num++;
			}

			lc->prtq = rte_realloc(lc->prtq, sizeof(*(lc->prtq)) *
				(lc->prtq_num + 1), RTE_CACHE_LINE_SIZE);
			if (lc->prtq == NULL) {
				RTE_LOG(ERR, USER1,
					"%s: failed to reallocate memory\n",
					__func__);
				return -ENOMEM;
			}
			lc->prtq[lc->prtq_num].rxqid = j;
			lc->prtq[lc->prtq_num].txqid = j;
			lc->prtq[lc->prtq_num].port = *prt;
			lc->prtq_num++;
		}
	}
	/*显示be的配置*/
	log_netbe_cfg(cfg);

	return 0;
}

#endif /* PORT_H_ */
