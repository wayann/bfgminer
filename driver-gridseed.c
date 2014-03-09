/*
 * Copyright 2014 Luke Dashjr
 * Copyright 2014 Nate Woolls
 * Copyright 2014 GridSeed Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <stdbool.h>

#include "deviceapi.h"
#include "lowlevel.h"
#include "lowl-vcom.h"
#include "gc3355.h"

BFG_REGISTER_DRIVER(gridseed_drv)

static
struct cgpu_info *gridseed_alloc_device(const char *path, struct device_drv *driver, struct gc3355_info *info)
{
	struct cgpu_info *device;

	device = calloc(1, sizeof(struct cgpu_info));
	device->drv = driver;
	device->device_path = strdup(path);
	device->device_fd = -1;
	device->threads = 1;
	device->device_data = info;

	return device;
}

static
int gridseed_open(const char *path)
{
	return serial_open(path, 115200, 1, true);
}

static
bool gridseed_detect_custom(const char *path, struct device_drv *driver, struct gc3355_info *info)
{
	int fd = gridseed_open(path);
	if(fd < 0)
		return false;

	const char detect_cmd[] = "55aac000909090900000000001000000";
	unsigned char detect_data[16];
	int size = sizeof(detect_data);

	hex2bin(detect_data, detect_cmd, size);

	int written = gc3355_write(fd, detect_data, size);
	if (written != size)
	{
		applog(LOG_ERR, "%s: Failed writing work to %s", gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	char buf[GC3355_READ_SIZE];
	int read = gc3355_read(fd, buf, GC3355_READ_SIZE);
	if (read != GC3355_READ_SIZE)
	{
		applog(LOG_ERR, "%s: Failed reading work from %s", gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	if (memcmp(buf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GC3355_READ_SIZE - 4) != 0)
	{
		applog(LOG_ERR, "%s: Invalid detect response from %s",
		       gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	uint32_t fw_version = le32toh(*(uint32_t *)(buf + 8));

	struct cgpu_info *device = gridseed_alloc_device(path, driver, info);

	if (serial_claim_v(path, driver))
		return false;
	
	if (!add_cgpu(device))
		return false;

	device->device_fd = fd;

	gc3355_init(device);

	applog(LOG_INFO, "Found %"PRIpreprv" at %s", device->proc_repr, path);
	applog(LOG_DEBUG, "%"PRIpreprv": Init: firmware=%d", device->proc_repr, fw_version);

	return true;
}

static
struct gc3355_info *gridseed_alloc_info()
{
	struct gc3355_info *info = calloc(1, sizeof(struct gc3355_info));
	if (unlikely(!info))
		quit(1, "Failed to malloc gc3355_info");

	info->freq = GC3355_DEFAULT_FREQUENCY;
	info->chips = GC3355_DEFAULT_CHIPS;

	return info;
}

static
bool gridseed_detect_one(const char *path)
{
	struct gc3355_info *info = gridseed_alloc_info();

	if (!gridseed_detect_custom(path, &gridseed_drv, info))
	{
		free(info);
		return false;
	}
	return true;
}

static
bool gridseed_lowl_probe(const struct lowlevel_device_info * const info)
{
	return vcom_lowl_probe_wrapper(info, gridseed_detect_one);
}

static
void gridseed_thread_shutdown(struct thr_info *thr)
{
	struct cgpu_info *device = thr->cgpu;
	serial_close(device->device_fd);

	free(thr->cgpu_data);
}

static
void gridseed_reset_state(struct thr_info *thr)
{
	struct gc3355_state * const state = thr->cgpu_data;

	memset(state->work, 0, sizeof(state->work));
	state->nonce = 0;
}

static
bool gridseed_thread_prepare(struct thr_info *thr)
{
	thr->cgpu_data = calloc(1, sizeof(*thr->cgpu_data));
	gridseed_reset_state(thr);
	
	return true;
}

static
bool gridseed_thread_init(struct thr_info *thr)
{
//	struct cgpu_info *device = thr->cgpu;
//
//	applog(LOG_DEBUG, "%"PRIpreprv": init", device->proc_repr);
//
//	if (device->device_fd == -1)
//	{
//
//	}
//
//	int fd = gridseed_open(device->device_path);
//	if (unlikely(-1 == fd))
//	{
//		applog(LOG_ERR, "%"PRIpreprv": Failed to open %s", device->proc_repr, device->device_path);
//		return false;
//	}
//
//	device->device_fd = fd;
//
//	gc3355_init(device);
//
//	applog(LOG_INFO, "%"PRIpreprv": Opened %s", device->proc_repr, device->device_path);

	return true;
}

static
int64_t gridseed_job_process_results(struct thr_info *thr, struct work *work, bool stopping)
{
	struct cgpu_info * const device = thr->cgpu;
	struct gc3355_state * const state = thr->cgpu_data;

	submit_nonce(thr, work, state->nonce);

	return state->hashrate;
}

static
bool gridseed_job_prepare(struct thr_info *thr, struct work *work, __maybe_unused uint64_t max_nonce)
{
	struct gc3355_state * const state = thr->cgpu_data;

	memcpy(state->work, "\x55\xaa\x1f\x00", 4);
	memcpy(state->work + 4, work->target, 32);
	memcpy(state->work + 36, work->midstate, 32);
	memcpy(state->work + 68, work->data, 80);
	memcpy(state->work + 148, "\xff\xff\xff\xff", 4);  // nonce_max
	memcpy(state->work + 152, "\x12\x34\x56\x78", 4);  // taskid

	work->blk.nonce = 0xffffffff;

	return true;
}

static
void gridseed_job_start(struct thr_info *thr)
{
	struct cgpu_info *device = thr->cgpu;

	gc3355_scrypt_reset(device);

	struct gc3355_info *info = (struct gc3355_info *)device->device_data;
	int fd = device->device_fd;
	struct gc3355_state * const state = thr->cgpu_data;

	int size = sizeof(state->work);

	struct timeval hashstart;
	timer_set_now(&hashstart);

	int written = gc3355_write(fd, state->work, size);
	if (written != size)
	{
		applog(LOG_ERR, "%"PRIpreprv": Failed writing work task", device->proc_repr);
		dev_error(device, REASON_DEV_COMMS_ERROR);
		job_start_abort(thr, true);
		return;
	}

	char buf[GC3355_READ_SIZE];

	int read = gc3355_read(fd, buf, GC3355_READ_SIZE);

	if(unlikely(read == -1))
	{
		// no job_start_abort for this...see driver-twinfury.c
		applog(LOG_ERR, "%"PRIpreprv": Work task read timeout", device->proc_repr);
		job_start_abort(thr, true);
		return;
	}

	if (buf[0] == 0x55 || buf[1] == 0x20)
	{
		uint32_t nonce = *(uint32_t *)(buf+4);
		applog(LOG_ERR, "%"PRIpreprv": Nonce read: %u (dec) %x (hex)", device->proc_repr, nonce, nonce);
		nonce = le32toh(nonce);
		applog(LOG_ERR, "%"PRIpreprv": Nonce converted: %u (dec) %x (hex)", device->proc_repr, nonce, nonce);


		state->nonce = nonce;
	}
	else
	{
		applog(LOG_ERR, "%"PRIpreprv": Unrecognized response", device->proc_repr);
		job_start_abort(thr, true);
		return;
	}

	mt_job_transition(thr);
	// TODO: Delay morework until right before it's needed
	timer_set_now(&thr->tv_morework);
	job_start_complete(thr);

	struct timeval hashend;
	timer_set_now(&hashend);

	int elapsed_ms = ms_tdiff(&hashend, &hashstart);
	state->hashrate = GRIDSEED_HASH_SPEED * (double)elapsed_ms * (double)(info->freq * info->chips);
}

struct device_drv gridseed_drv = {
	// metadata
	.dname = "gridseed",
	.name = "GSD",

	// detect device
	.lowl_probe = gridseed_lowl_probe,

	// initialize device
	.thread_prepare = gridseed_thread_prepare,
	.thread_init = gridseed_thread_init,

	// mining - async
	.minerloop = minerloop_async,

	// async mining hooks
	.job_prepare = gridseed_job_prepare,
	.job_start = gridseed_job_start,
	.job_process_results = gridseed_job_process_results,

	// teardown device
	.thread_shutdown = gridseed_thread_shutdown,
};
