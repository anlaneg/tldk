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

#ifndef _STREAM_H_
#define _STREAM_H_

#include "ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common structure that must be present as first field in all partcular
 * L4 (UDP/TCP, etc.) stream implementations.
 */
struct tle_stream {

	STAILQ_ENTRY(tle_stream) link;
	struct tle_ctx *ctx;

	//流类型，ipv4或者ipv6
	uint8_t type;	       /* TLE_V4 or TLE_V6 */

	/* Stream address information. */
	union l4_ports port;//源目的端口信息
	//流的port地址将与此值与，与后与port进行对比，相同才能匹配
	//原则上只有匹配目的ip地址与目的端口地址
	union l4_ports pmsk;


	union {
		struct {
			union ipv4_addrs addr;
			union ipv4_addrs mask;
		} ipv4;//源目的地址
		struct {
			union ipv6_addrs addr;
			union ipv6_addrs mask;
		} ipv6;
	};
};

//自ctx->streams中分配num个tle_stream,存储在s数组中
static inline uint32_t
get_streams(struct tle_ctx *ctx, struct tle_stream *s[], uint32_t num)
{
	struct tle_stream *p;
	uint32_t i, n;

	rte_spinlock_lock(&ctx->streams.lock);

	/*使用能满足的最小数目stream,并收集到s中*/
	n = RTE_MIN(ctx->streams.nb_free, num);
	for (i = 0, p = STAILQ_FIRST(&ctx->streams.free);
			i != n;
			i++, p = STAILQ_NEXT(p, link))
		s[i] = p;

	//无空闲stream
	if (p == NULL)
		/* we retrieved all free entries */
		STAILQ_INIT(&ctx->streams.free);
	else
	    //更新free，使其指向下一个空闲的stream
		STAILQ_FIRST(&ctx->streams.free) = p;

	//数量减少
	ctx->streams.nb_free -= n;
	rte_spinlock_unlock(&ctx->streams.lock);
	return n;
}

//分配一个tle_stream
static inline struct tle_stream *
get_stream(struct tle_ctx *ctx)
{
	struct tle_stream *s;

	s = NULL;
	//无空闲节点时，返回NULL
	if (ctx->streams.nb_free == 0)
		return s;

	get_streams(ctx, &s, 1);
	return s;
}

//向ctx->stream中存放一个tle_stream,head变量指出是否存在头部
static inline void
put_stream(struct tle_ctx *ctx, struct tle_stream *s, int32_t head)
{
	s->type = TLE_VNUM;
	rte_spinlock_lock(&ctx->streams.lock);
	if (head != 0)
		STAILQ_INSERT_HEAD(&ctx->streams.free, s, link);
	else
		STAILQ_INSERT_TAIL(&ctx->streams.free, s, link);
	ctx->streams.nb_free++;
	rte_spinlock_unlock(&ctx->streams.lock);
}

/* calculate number of drbs per stream. */
static inline uint32_t
calc_stream_drb_num(const struct tle_ctx *ctx, uint32_t obj_num)
{
	uint32_t num;

	num = (ctx->prm.max_stream_sbufs + obj_num - 1) / obj_num;
	num = num + num / 2;
	num = RTE_MAX(num, RTE_DIM(ctx->dev) + 1);
	return num;
}

static inline uint32_t
drb_nb_elem(const struct tle_ctx *ctx)
{
	return (ctx->prm.send_bulk_size != 0) ?
		ctx->prm.send_bulk_size : MAX_PKT_BURST;
}

//目的地查询
static inline int32_t
stream_get_dest(struct tle_stream *s, const void *dst_addr,
	struct tle_dest *dst)
{
	int32_t rc;
	const struct in_addr *d4;
	const struct in6_addr *d6;
	struct tle_ctx *ctx;
	struct tle_dev *dev;

	ctx = s->ctx;

	/* it is here just to keep gcc happy. */
	d4 = NULL;
	d6 = NULL;

	//查路由，找下一跳
	if (s->type == TLE_V4) {
		d4 = dst_addr;
		rc = ctx->prm.lookup4(ctx->prm.lookup4_data, d4, dst);
	} else if (s->type == TLE_V6) {
		d6 = dst_addr;
		rc = ctx->prm.lookup6(ctx->prm.lookup6_data, d6, dst);
	} else
		rc = -ENOENT;//无法查询到路由

	if (rc < 0 || dst->dev == NULL || dst->dev->ctx != ctx)
		return -ENOENT;

	dev = dst->dev;
	dst->ol_flags = dev->tx.ol_flags[s->type];

	if (s->type == TLE_V4) {
		struct rte_ipv4_hdr *l3h;
		l3h = (struct rte_ipv4_hdr *)(dst->hdr + dst->l2_len);
		//填充ip层源ip地址及目的ip地址(填写至hdr中）
		l3h->src_addr = dev->prm.local_addr4.s_addr;
		l3h->dst_addr = d4->s_addr;
	} else {
		struct rte_ipv6_hdr *l3h;
		l3h = (struct rte_ipv6_hdr *)(dst->hdr + dst->l2_len);
		rte_memcpy(l3h->src_addr, &dev->prm.local_addr6,
			sizeof(l3h->src_addr));
		rte_memcpy(l3h->dst_addr, d6, sizeof(l3h->dst_addr));
	}

	return dev - ctx->dev;
}

#ifdef __cplusplus
}
#endif

#endif /* _STREAM_H_ */
