/*
 * Copyright (c) 2016-2017  Intel Corporation.
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

#ifndef _CTX_H_
#define _CTX_H_

#include <rte_spinlock.h>
#include <rte_vect.h>
#include <tle_dring.h>
#include <tle_ctx.h>

#include "port_bitmap.h"
#include "osdep.h"
#include "net_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tle_dport {
	struct tle_pbm use; /* ports in use. */
	//监听表（其内容可以为tcp监听表，udp监听表，例如：tle_tcp_stream）
	struct tle_stream *streams[MAX_PORT_NUM/*主机序port*/]; /* port to stream. */
};

struct tle_dev {
	struct tle_ctx *ctx;/*指向其对应的context,如果为空，则此结构未分配*/
	struct {
		/* used by FE. */
		uint64_t ol_flags[TLE_VNUM];
		//ipv4,ipv6各有一个id号生成变量
		rte_atomic32_t packet_id[TLE_VNUM];

		/* used by FE & BE. */
		struct tle_dring dr;//用于发送报文
	} tx;
	struct tle_dev_param prm; /* copy of device parameters. */

	/*按ipv4/ipv6进行划分的目的port*/
	struct tle_dport *dp[TLE_VNUM]; /* device L4 ports */
};

struct tle_ctx {
	struct tle_ctx_param prm;
	uint32_t cycles_ms_shift;  /* to convert from cycles to ms */
	struct {
	    //锁，保护streams结构体
		rte_spinlock_t lock;
		 //空闲stream的数目
		uint32_t nb_free; /* number of free streams. */
		//tle_stream的空闲链表
		STAILQ_HEAD(, tle_stream) free;
		void *buf; /* space allocated for streams */
	} streams;

	rte_spinlock_t dev_lock;
	/*dev数据有效长度*/
	uint32_t nb_dev;
	/*port bitmap记录哪些port已被占用*/
	struct tle_pbm use[TLE_VNUM]; /* all ports in use. */
	struct tle_dev dev[RTE_MAX_ETHPORTS];
};

struct stream_ops {
	int (*init_streams)(struct tle_ctx *);
	void (*fini_streams)(struct tle_ctx *);
	void (*free_drbs)(struct tle_stream *, struct tle_drb *[], uint32_t);
};

extern struct stream_ops tle_stream_ops[TLE_PROTO_NUM];

int stream_fill_ctx(struct tle_ctx *ctx, struct tle_stream *s,
	const struct sockaddr *laddr, const struct sockaddr *raddr);

int stream_clear_ctx(struct tle_ctx *ctx, struct tle_stream *s);

#ifdef __cplusplus
}
#endif

#endif /* _UDP_IMPL_H_ */
