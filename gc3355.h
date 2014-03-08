//
//  gc3355.h
//  bfgminer
//
//  Created by Nathanial Woolls on 3/7/14.
//  Copyright (c) 2014 Nate Woolls. All rights reserved.
//

#ifndef bfgminer_gc3355_h
#define bfgminer_gc3355_h

#include <stdint.h>

#include "miner.h"

#define GC3355_DEFAULT_FREQUENCY	600

struct gc3355_info
{
	uint16_t freq;
};

extern
int gc3355_read(int fd, char *buf, int size);

extern
ssize_t gc3355_write(int fd, const void * const buf, const size_t size);

extern
void gc3355_init(struct cgpu_info *device);

#endif
