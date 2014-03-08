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

BFG_REGISTER_DRIVER(gridseed_drv)

static
bool gridseed_lowl_match(const struct lowlevel_device_info * const info)
{
	return lowlevel_match_product(info, "GridSeed");
}

static
bool gridseed_lowl_probe(const struct lowlevel_device_info * const info)
{
	return false;//vcom_lowl_probe_wrapper(info, bifury_detect_one);
}

struct device_drv gridseed_drv = {
	.dname = "gridseed",
	.name = "GSD",
	.lowl_match = gridseed_lowl_match,
	.lowl_probe = gridseed_lowl_probe,
};