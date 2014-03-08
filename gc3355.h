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
#define GC3355_DEFAULT_CHIPS		5

#define GC3355_READ_SIZE			12
#define GRIDSEED_HASH_SPEED			0.0851128926	// in ms

struct gc3355_info
{
	uint16_t freq;
	int chips;
};

struct gc3355_state
{
	// request
	uint8_t work[156];

	// response
	uint32_t nonce;

	// stats
	int64_t hashrate;
};

extern
int gc3355_read(int fd, char *buf, int size);

extern
ssize_t gc3355_write(int fd, const void * const buf, const size_t size);

extern
void gc3355_init(struct cgpu_info *device);

#endif
