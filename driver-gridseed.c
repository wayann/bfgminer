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

#define GRIDSEED_READ_SIZE			12

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
bool gridseed_detect_custom(const char *path, struct device_drv *driver, struct gc3355_info *info)
{
	int fd = serial_open(path, 115200, 1, true);

	if(fd < 0)
		return false;



	const char detect_cmd[] = "55aac000909090900000000001000000";
	unsigned char detect_data[16];


	hex2bin(detect_data, detect_cmd, sizeof(detect_data));

	int size = sizeof(detect_data);
	int written = gc3355_write(fd, detect_data, size);
	if (written != size)
	{
		applog(LOG_ERR, "%s: Failed writing detect data to %s",
		       gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	char buf[GRIDSEED_READ_SIZE];
	int read = gc3355_read(fd, buf, GRIDSEED_READ_SIZE);
	if (read != GRIDSEED_READ_SIZE)
	{
		applog(LOG_ERR, "%s: Failed reading detect data to %s",
		       gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	if (memcmp(buf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GRIDSEED_READ_SIZE - 4) != 0)
	{
		applog(LOG_ERR, "%s: Bad detect response from %s",
		       gridseed_drv.dname, path);
		serial_close(fd);
		return false;
	}

	uint32_t fw_version = le32toh(*(uint32_t *)(buf + 8));

	struct cgpu_info *device = gridseed_alloc_device(path, driver, info);

	device->device_fd = fd;
	gc3355_init(device);

	serial_close(fd);

	device->device_fd = -1;

	if (serial_claim_v(path, driver))
		return false;

	
	if (!add_cgpu(device))
		return false;

	applog(LOG_INFO, "Found %"PRIpreprv" at %s", device->proc_repr, path);
	applog(LOG_DEBUG, "%"PRIpreprv": Init: firmware=%d", device->proc_repr, fw_version);

	return true;
}

static
bool gridseed_detect_one(const char *path)
{
	struct gc3355_info *info = calloc(1, sizeof(struct gc3355_info));
	if (unlikely(!info))
		quit(1, "Failed to malloc gridseed_info");

	info->freq = GC3355_DEFAULT_FREQUENCY;

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

struct device_drv gridseed_drv = {
	.dname = "gridseed",
	.name = "GSD",
	.lowl_probe = gridseed_lowl_probe,
};
