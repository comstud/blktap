/* 
 * Copyright (c) 2010, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Local persistent cache: write any sectors not found in the leaf back to the 
 * leaf.
 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "vhd.h"
#include "tapdisk.h"
#include "tapdisk-utils.h"
#include "tapdisk-driver.h"
#include "tapdisk-server.h"
#include "tapdisk-interface.h"

#ifdef DEBUG
#define DBG(_f, _a...) tlog_write(TLOG_DBG, _f, ##_a)
#else
#define DBG(_f, _a...) ((void)0)
#endif

#define WARN(_f, _a...) tlog_write(TLOG_WARN, _f, ##_a)
#define BUG()           td_panic()
#define BUG_ON(_cond)   if (_cond) { td_panic(); }

#define LOCAL_CACHE_REQUESTS            (TAPDISK_DATA_REQUESTS << 3)

typedef struct local_cache              local_cache_t;

struct local_cache_request {
	int                             err;
	char                           *buf;
	int                             secs;
	td_request_t                    treq;
	local_cache_t                  *cache;
	enum { LC_READ = 1, LC_WRITE }  phase;
};
typedef struct local_cache_request      local_cache_request_t;

struct local_cache {
	char                           *name;

	local_cache_request_t           requests[LOCAL_CACHE_REQUESTS];
	local_cache_request_t          *request_free_list[LOCAL_CACHE_REQUESTS];
	int                             requests_free;
};

static void local_cache_complete_req(td_request_t, int);

static inline local_cache_request_t *
local_cache_get_request(local_cache_t *cache)
{
	if (!cache->requests_free)
		return NULL;

	return cache->request_free_list[--cache->requests_free];
}

static inline void
local_cache_put_request(local_cache_t *cache, local_cache_request_t *lreq)
{
	free(lreq->buf);
	memset(lreq, 0, sizeof(local_cache_request_t));
	cache->request_free_list[cache->requests_free++] = lreq;
}

static int
local_cache_open(td_driver_t *driver, const char *name, td_flag_t flags)
{
	int i, err; 
	local_cache_t *cache;

	cache = (local_cache_t *)driver->data;
	err   = tapdisk_namedup(&cache->name, (char *)name);
	if (err)
		return -ENOMEM;
	cache->requests_free = LOCAL_CACHE_REQUESTS;
	for (i = 0; i < LOCAL_CACHE_REQUESTS; i++)
		cache->request_free_list[i] = cache->requests + i;

	DPRINTF("Opening local cache for %s\n", cache->name);
	return 0;
}

static int
local_cache_close(td_driver_t *driver)
{
	local_cache_t *cache;

	cache = (local_cache_t *)driver->data;
	DPRINTF("Closing local cache for %s\n", cache->name);

	free(cache->name);
	return 0;
}

static void
local_cache_complete_read(local_cache_t *cache, local_cache_request_t *lreq)
{
	td_vbd_t *vbd = lreq->treq.image->private;
	td_request_t clone;
	int i;


	if (lreq->err) {
		td_complete_request(lreq->treq, lreq->err);
		local_cache_put_request(cache, lreq);
		return;
	}

	for (i = 0; i < lreq->treq.secs; i++) {
		off_t off = i << VHD_SECTOR_SHIFT;
		//DPRINTF(">>> populating sec 0x%08llx\n", lreq->treq.sec + i);
		memcpy(lreq->treq.buf + off, lreq->buf + off, VHD_SECTOR_SIZE);
	}

	td_complete_request(lreq->treq, lreq->err);

	lreq->phase   = LC_WRITE;
	lreq->secs    = lreq->treq.secs;
	lreq->err     = 0;

	clone         = lreq->treq;
	clone.op      = TD_OP_WRITE;
	clone.buf     = lreq->buf;
	clone.cb      = local_cache_complete_req;
	clone.cb_data = lreq;
	clone.image   = tapdisk_vbd_first_image(vbd);

	td_queue_write(clone.image, clone);
}

static void
local_cache_complete_write(local_cache_t *cache, local_cache_request_t *lreq)
{
	local_cache_put_request(cache, lreq);
}

static void
local_cache_complete_req(td_request_t treq, int err)
{
	local_cache_request_t *lreq = treq.cb_data;
	local_cache_t *cache = lreq->cache;

	BUG_ON(lreq->secs == 0);
	BUG_ON(lreq->secs < treq.secs);

	lreq->secs -= treq.secs;
	lreq->err   = lreq->err ? : err;

	if (lreq->secs)
		return;

	switch (lreq->phase) {
	case LC_READ:
		local_cache_complete_read(cache, lreq);
		break;

	case LC_WRITE:
		local_cache_complete_write(cache, lreq);
		break;

	default:
		BUG();
	}
}

static void
local_cache_queue_read(td_driver_t *driver, td_request_t treq)
{
	int err;
	char *buf;
	size_t size;
	td_request_t clone;
	local_cache_request_t *lreq;
	local_cache_t *cache;

	//DPRINTF("LocalCache: read request! %lld (%d secs)\n", treq.sec, 
	//treq.secs);

	cache = (local_cache_t *)driver->data;

	clone = treq;
	size  = treq.secs << VHD_SECTOR_SHIFT;

	lreq = local_cache_get_request(cache);
	if (!lreq) {
		//EPRINTF("FAILED TO get lreq! %lld\n", treq.sec);
		goto out;
	}

	err = posix_memalign((void **)&buf, 4096, size);
	if (err) {
		EPRINTF("FAILED TO posix_memalign! %d\n", err);
		local_cache_put_request(cache, lreq);
		goto out;
	}

	lreq->treq    = treq;
	lreq->cache   = cache;
	lreq->buf     = buf;

	lreq->phase   = LC_READ;
	lreq->secs    = lreq->treq.secs;
	lreq->err     = 0;

	clone.buf     = buf;
	clone.cb      = local_cache_complete_req;
	clone.cb_data = lreq;

out:
	td_forward_request(clone);
}


static void
local_cache_queue_write(td_driver_t *driver, td_request_t treq)
{
	DPRINTF("Local cache: write request! (ERROR)\n");
	td_complete_request(treq, -EPERM);
}

static int
local_cache_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	return -EINVAL;
}

static int
local_cache_validate_parent(td_driver_t *driver,
			    td_driver_t *pdriver, td_flag_t flags)
{
	if (strcmp(driver->name, pdriver->name))
		return -EINVAL;

	return 0;
}

static void
local_cache_debug(td_driver_t *driver)
{
	local_cache_t *cache;

	cache = (local_cache_t *)driver->data;

	WARN("LOCAL CACHE %s\n", cache->name);
}

struct tap_disk tapdisk_local_cache = {
	.disk_type                  = "tapdisk_local_cache",
	.flags                      = 0,
	.private_data_size          = sizeof(local_cache_t),
	.td_open                    = local_cache_open,
	.td_close                   = local_cache_close,
	.td_queue_read              = local_cache_queue_read,
	.td_queue_write             = local_cache_queue_write,
	.td_get_parent_id           = local_cache_get_parent_id,
	.td_validate_parent         = local_cache_validate_parent,
	.td_debug                   = local_cache_debug,
};
