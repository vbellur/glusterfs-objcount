/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _MARKER_COUNT_H
#define _MARKER_COUNT_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "marker.h"
#include "xlator.h"
#include "defaults.h"
#include "uuid.h"
#include "call-stub.h"

#define GF_COUNT_DIRTY_KEY "trusted.glusterfs.count.dirty"

int32_t
mc_start_update_count (call_frame_t *frame, xlator_t *this);

int32_t
mc_update_count (marker_local_t *local, int count);

#endif
