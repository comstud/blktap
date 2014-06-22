/*
 * Copyright (C) 2014 Rackspace Hosting, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2.1 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef BUILD_WITH_THREADS
#include <pthread.h>
#endif

#include "libvhd.h"

struct _vhd2raw_options {
    char *source;
    char *target;
    char direct;
    char force;
    char sparse;
    char pwrite;
#ifdef BUILD_WITH_THREADS
    char threads;
    char read_ahead_blocks;
#endif
    int blk_size;
};

#ifdef BUILD_WITH_THREADS
struct _read_buffer_list
{
    void *read_buf;
    size_t read_bytes;
    struct _read_buffer_list *next;
};
#endif

struct _vhd2raw_ctx {
    struct _vhd2raw_options  opts;
    int output_fd;
    int raw_device;
    int bytes_skipped;
    uint64_t cur_write_pos;
    uint64_t next_write_pos;
    void *compare_buf;

#ifdef BUILD_WITH_THREADS
    int write_result;
    char done_reading;
    pthread_mutex_t thr_lock;
    pthread_cond_t thr_rcond;
    pthread_cond_t thr_wcond;
    struct _read_buffer_list *write_ready_head;
    struct _read_buffer_list *write_ready_tail;
    struct _read_buffer_list *read_ready_head;
    struct _read_buffer_list *read_ready_tail;
#endif
};

static void _usage(void)
{
	printf("options: [-h] [-b blk_size] [-d] [-f] [-t] [-r <blocks>] [-S] [-P] <file.vhd> <output>\n");
}

static int _vhd2raw_ctx_init(struct _vhd2raw_ctx *ctx)
{
    ctx->opts.source = NULL;
    ctx->opts.target = NULL;
    ctx->opts.direct = 0;
    ctx->opts.blk_size = 1024 * 1024;
    ctx->opts.force = 0;
    ctx->opts.sparse = 1;
    ctx->opts.pwrite = 1;
#ifdef BUILD_WITH_THREADS
    ctx->opts.threads = 0;
    ctx->opts.read_ahead_blocks = 1;
#endif

    ctx->output_fd = -1;
    ctx->raw_device = 0;
    ctx->bytes_skipped = 0;
    ctx->cur_write_pos = 0;
    ctx->next_write_pos = 0;
    ctx->compare_buf = NULL;

#ifdef BUILD_WITH_THREADS
    ctx->write_result = 0;
    ctx->done_reading = 0;
    pthread_mutex_init(&(ctx->thr_lock), NULL);
    pthread_cond_init(&(ctx->thr_rcond), NULL);
    pthread_cond_init(&(ctx->thr_wcond), NULL);
    ctx->write_ready_head = NULL;
    ctx->write_ready_tail = NULL;
    ctx->read_ready_head = NULL;
    ctx->read_ready_tail = NULL;
#endif

    return 0;
}

static void _vhd2raw_ctx_deinit(struct _vhd2raw_ctx *ctx)
{
    if (ctx->output_fd >= 0)
    {
        close(ctx->output_fd);
    }

    if (ctx->compare_buf != NULL)
    {
        free(ctx->compare_buf);
    }

#ifdef BUILD_WITH_THREADS

    /* FIXME: Cleanup read buffers */

    pthread_mutex_destroy(&(ctx->thr_lock));
    pthread_cond_destroy(&(ctx->thr_rcond));
    pthread_cond_destroy(&(ctx->thr_wcond));
#endif
}

static int _open_output(struct _vhd2raw_ctx *ctx)
{
    int err;
    struct stat sb;
    int oflags;

    err = stat(ctx->opts.target, &sb);
    if (err != 0)
    {
        if (errno != ENOENT)
            return errno ? -errno : -EINVAL;
    }
    else if (sb.st_mode & S_IFBLK)
    {
        ctx->raw_device = 1;
    }

    oflags = O_RDWR;
#ifdef O_DIRECT
    if (ctx->opts.direct)
        oflags |= O_DIRECT;
#endif

    if (!ctx->raw_device)
    {
        oflags |= O_CREAT|O_TRUNC;
        if (!ctx->opts.force)
        {
            oflags |= O_EXCL;
        }
    }

    ctx->output_fd = open(ctx->opts.target, oflags, 0600);
    if (ctx->output_fd < 0)
    {
        err = errno ? errno : EINVAL;
        return -err;
    }

    return 0;
}

static int _write_output(struct _vhd2raw_ctx *ctx, void *read_buf,
                         size_t read_bytes)
{
    size_t write_size_left = read_bytes;
    size_t write_bytes;
    int blk_size = ctx->opts.blk_size;
    ssize_t bytes_written;
    off_t ls_pos;

    while (write_size_left)
    {
        write_bytes = (write_size_left > blk_size) ? blk_size :
                                                     write_size_left;
        if (ctx->opts.sparse &&
                !memcmp(read_buf, ctx->compare_buf, write_bytes))
        {
            ctx->bytes_skipped += write_bytes;
        }
        else
        {
            if (ctx->opts.pwrite)
            {
                bytes_written = pwrite(ctx->output_fd, read_buf, write_bytes,
                                       ctx->next_write_pos);
            }
            else
            {
                if (ctx->cur_write_pos != ctx->next_write_pos)
                {
                    ls_pos = lseek(ctx->output_fd, ctx->next_write_pos,
                                   SEEK_SET);
                    if (ls_pos == (off_t)-1)
                    {
                        return errno ? -errno : -EINVAL;
                    }
                    ctx->cur_write_pos = ctx->next_write_pos;
                }

                bytes_written = write(ctx->output_fd, read_buf, write_bytes);
            }

            if (bytes_written < 0)
            {
                return errno ? -errno : -EINVAL;
            }

            ctx->cur_write_pos += bytes_written;
        }

        ctx->next_write_pos += write_bytes;
        write_size_left -= write_bytes;
        read_buf += write_bytes;
    }

    return 0;
}

static int _write_without_thread(struct _vhd2raw_ctx *ctx,
                                 vhd_context_t *vhd)
{
    uint64_t cur_read_pos = 0;
    uint64_t read_size_left = vhd->footer.curr_size;
    size_t read_bytes;
    void *read_buf;
    int err;

    err = posix_memalign(&read_buf, VHD_SECTOR_SIZE, VHD_BLOCK_SIZE);
    if (err)
    {
        return err;
    }

    while (read_size_left)
    {
        read_bytes = (read_size_left > VHD_BLOCK_SIZE) ? VHD_BLOCK_SIZE :
                                                         read_size_left;
        err = vhd_io_read_bytes(vhd, read_buf, read_bytes, cur_read_pos);
        if (err < 0)
        {
            return err;
        }

        cur_read_pos += read_bytes;
        read_size_left -= read_bytes;

        err = _write_output(ctx, read_buf, read_bytes);
        if (err < 0)
        {
            break;
        }
    }

    return err;
}

#ifdef BUILD_WITH_THREADS
static void _writer_thread(struct _vhd2raw_ctx *ctx)
{
    struct _read_buffer_list *buf_entry;
    struct _read_buffer_list *write_ready_head = NULL;
    struct _read_buffer_list *read_ready_head = NULL;
    struct _read_buffer_list *read_ready_tail = NULL;
    void *cur_buf;
    int err = 0;
    int read_ready_num = 0;

    while(ctx->write_ready_head || 
          write_ready_head || !ctx->done_reading)
    for(;;)
    {
        if (write_ready_head != NULL)
        {
            buf_entry = write_ready_head;
        }
        else
        {
            pthread_mutex_lock(&(ctx->thr_lock));
            while ((buf_entry = ctx->write_ready_head) == NULL)
            {
                if (ctx->done_reading)
                {
                    ctx->write_result = 0;
                    pthread_mutex_unlock(&(ctx->thr_lock));
                    return;
                }
                pthread_cond_wait(&(ctx->thr_wcond), &(ctx->thr_lock));
            }

            /* Take ownership of full list */
            ctx->write_ready_head = NULL;
            ctx->write_ready_tail = NULL;

            pthread_mutex_unlock(&(ctx->thr_lock));
        }

        write_ready_head = buf_entry->next;

        err = _write_output(ctx, buf_entry->read_buf,
                            buf_entry->read_bytes);

        buf_entry->next = read_ready_head;
        read_ready_head = buf_entry;
        if (read_ready_tail == NULL)
        {
            read_ready_tail = buf_entry;
        }

        if (++read_ready_num >= (ctx->opts.read_ahead_blocks / 2))
        {
            pthread_mutex_lock(&(ctx->thr_lock));

            read_ready_tail->next = ctx->read_ready_head;
            ctx->read_ready_head = read_ready_head;
            if (ctx->read_ready_tail == NULL)
            {
                ctx->read_ready_tail = read_ready_tail;
            }

            printf("Signaling reader...\n");
            pthread_cond_signal(&(ctx->thr_rcond));
            pthread_mutex_unlock(&(ctx->thr_lock));

            read_ready_num = 0;
            read_ready_head = NULL;
            read_ready_tail = NULL;
        }

        if (err)
        {
            break;
        }
    }

    ctx->write_result = err;
}

static int _write_with_thread(struct _vhd2raw_ctx *ctx, vhd_context_t *vhd)
{
    uint64_t cur_read_pos = 0;
    uint64_t read_size_left = vhd->footer.curr_size;
    size_t read_bytes;
    struct _read_buffer_list *buf_entry;
    pthread_t thr_id;
    int err;
    int num_buffers = 0;

    err = pthread_create(&thr_id, NULL, (void *(*)(void *))_writer_thread,
                         ctx);
    if (err)
        return err;


    pthread_mutex_lock(&(ctx->thr_lock));

    while (read_size_left)
    {
        buf_entry = ctx->read_ready_head;
        if (buf_entry == NULL)
        {
            if (num_buffers == ctx->opts.read_ahead_blocks)
            {
                printf("Waiting for read buffer...\n");
                pthread_cond_wait(&(ctx->thr_rcond), &(ctx->thr_lock));
                printf("Reader woken up...\n");
                continue;
            }

            num_buffers++;

            pthread_mutex_unlock(&(ctx->thr_lock));

            buf_entry = malloc(sizeof(struct _read_buffer_list));
            if (buf_entry == NULL)
            {
                err = errno ? -errno : -ENOMEM;
                break;
            }

            err = posix_memalign(&(buf_entry->read_buf), VHD_SECTOR_SIZE,
                                 VHD_BLOCK_SIZE);
            if (err)
            {
                err = -err;
                free(buf_entry);
                break;
            }
        }
        else
        {
            ctx->read_ready_head = buf_entry->next;
            if (!ctx->read_ready_head)
            {
                ctx->read_ready_tail = NULL;
            }

            pthread_mutex_unlock(&(ctx->thr_lock));
        }

        buf_entry->read_bytes = (read_size_left > VHD_BLOCK_SIZE) ?
                                 VHD_BLOCK_SIZE : read_size_left;
        err = vhd_io_read_bytes(vhd, buf_entry->read_buf,
                                buf_entry->read_bytes, cur_read_pos);
        if (err < 0)
        {
            free(buf_entry->read_buf);
            free(buf_entry);
            break;
        }

        cur_read_pos += read_bytes;
        read_size_left -= read_bytes;

        buf_entry->next = NULL;

        pthread_mutex_lock(&(ctx->thr_lock));

        if (ctx->write_ready_tail == NULL)
        {
            ctx->write_ready_head = buf_entry;
            pthread_cond_signal(&(ctx->thr_wcond));
        }
        else
        {
            ctx->write_ready_tail->next = buf_entry;
        }

        ctx->write_ready_tail = buf_entry;

    }

    ctx->done_reading = 1;

    if (ctx->write_ready_head == NULL)
        pthread_cond_signal(&(ctx->thr_wcond));

    pthread_mutex_lock(&(ctx->thr_lock));

    pthread_join(thr_id, NULL);

    return err ? err : ctx->write_result;
}

#endif

static int _vhd_to_raw(struct _vhd2raw_ctx *ctx)
{
    int err;
    vhd_context_t vhd;

    err = vhd_open(&vhd, ctx->opts.source,
                   VHD_OPEN_RDONLY | VHD_OPEN_IGNORE_DISABLED);
    if (err)
    {
        return err;
    }

    if ((err = _open_output(ctx)) < 0)
    {
        vhd_close(&vhd);
        return err;
    }

    if (!ctx->raw_device)
    {
        err = ftruncate(ctx->output_fd, vhd.footer.curr_size);
        if (err < 0)
        {
            vhd_close(&vhd);
            return err;
        }
    }

    printf("Converting image of size %llu...\n",
           (unsigned long long)vhd.footer.curr_size);

#ifdef BUILD_WITH_THREADS
    if (ctx->opts.threads)
    {
        err = _write_with_thread(ctx, &vhd);
    }
    else
#endif
    {
        err = _write_without_thread(ctx, &vhd);
    }

    vhd_close(&vhd);

    return err;
}

int
vhd_util_vhd2raw(int argc, char **argv)
{
    struct _vhd2raw_ctx vhd2raw_ctx;
	int c;

	if (!argc || !argv) {
        _usage();
		return -EINVAL;
	}

    _vhd2raw_ctx_init(&vhd2raw_ctx);

	optind = 0;
	while ((c = getopt(argc, argv, "b:r:dfthSP")) != -1) {
		switch (c) {
        case 'b':
            vhd2raw_ctx.opts.blk_size = atoi(optarg);
            if (vhd2raw_ctx.opts.blk_size < 0 ||
                    vhd2raw_ctx.opts.blk_size > (int)VHD_BLOCK_SIZE)
            {
                _vhd2raw_ctx_deinit(&vhd2raw_ctx);
                printf("Error: Invalid block size: Must be >= 0 and less "
                       "than %llu\n", VHD_BLOCK_SIZE);
                _usage();
                return -EINVAL;
            }
            else if (!vhd2raw_ctx.opts.blk_size)
            {
                vhd2raw_ctx.opts.blk_size = VHD_BLOCK_SIZE;
            }
            break;
        case 'd':
            vhd2raw_ctx.opts.direct = 1;
            break;
        case 'f':
            vhd2raw_ctx.opts.force = 1;
            break;
        case 'r':
#ifdef BUILD_WITH_THREADS
            vhd2raw_ctx.opts.read_ahead_blocks = atoi(optarg);
            if ((vhd2raw_ctx.opts.read_ahead_blocks <= 0) ||
                (vhd2raw_ctx.opts.read_ahead_blocks > 100))
            {
                printf("Error: read_ahead_blocks must be > 0 and <= 100\n");
                return -EINVAL;
            }
            break;
#else
            printf("Error: threads are not available.\n");
            return -EINVAL;
#endif
        case 't':
#ifdef BUILD_WITH_THREADS
            vhd2raw_ctx.opts.threads = 1;
            break;
#else
            printf("Error: threads are not available.\n");
            return -EINVAL;
#endif
        case 'S':
            vhd2raw_ctx.opts.sparse = 0;
            break;
        case 'P':
            vhd2raw_ctx.opts.pwrite = 0;
            break;
		case 'h':
            _vhd2raw_ctx_deinit(&vhd2raw_ctx);
            _usage();
            return 0;
		default:
            _vhd2raw_ctx_deinit(&vhd2raw_ctx);
            _usage();
            return -EINVAL;
		}
	}

    if ((argc - optind) != 2)
    {
        _vhd2raw_ctx_deinit(&vhd2raw_ctx);
        _usage();
        return -EINVAL;
    }

    c = posix_memalign(&(vhd2raw_ctx.compare_buf), VHD_SECTOR_SIZE,
                       vhd2raw_ctx.opts.blk_size);
    if (c)
    {
        _vhd2raw_ctx_deinit(&vhd2raw_ctx);
        printf("Out of memory\n");
        return c;
    }

    memset(vhd2raw_ctx.compare_buf, 0, vhd2raw_ctx.opts.blk_size);

    vhd2raw_ctx.opts.source = argv[optind];
    vhd2raw_ctx.opts.target = argv[optind + 1];

    c = _vhd_to_raw(&vhd2raw_ctx);
    _vhd2raw_ctx_deinit(&vhd2raw_ctx);

    if (c < 0)
    {
        printf("Error during converstion: %d\n", c);
    }

    return c;
}
