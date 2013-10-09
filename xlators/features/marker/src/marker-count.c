/*
   Copyright (c) 2008-2013 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "xlator.h"
#include "defaults.h"
#include "libxlator.h"
#include "marker.h"
#include "marker-mem-types.h"
#include "marker-count.h"
#include "marker-common.h"
#include "byte-order.h"


int32_t
mc_xattrop_done (call_frame_t *frame)
{
        marker_local_t  *local = NULL;
        int32_t         ret  = -1;

        if (!frame || !frame->local)
                goto out;

        local = (marker_local_t *) frame->local;
        frame->local = NULL;
        STACK_DESTROY (frame->root);
        ret = marker_local_unref (local);

out:
        return ret;
}

int32_t
mc_create_frame (marker_local_t *local, call_frame_t **frame)
{
        call_frame_t    *new_frame      = NULL;
        int32_t         ret             = -1;
        xlator_t        *this           = NULL;

        this = THIS;

        if (!this || !this->ctx)
                goto out;

        new_frame = create_frame (this, this->ctx->pool);
        if (!new_frame)
                goto out;

        if (frame)
                *frame = new_frame;

        new_frame->local = (void *) local;

        ret = 0;
out:
        return ret;
}

int32_t
mc_mark_clean_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        marker_local_t          *local = NULL;
        int32_t                  ret   = -1;
        int32_t                  done  = 0;

        GF_ASSERT (frame);

        local = frame->local;

        if (!local) {
                done = 1;
                goto out;
        }

        ret = 0;

        if (local->loc.path && strcmp (local->loc.path, "/") == 0) {
                done = 1;
                goto out;
        }

        if (__is_root_gfid (local->loc.gfid)) {
                done = 1;
                goto out;
        }

        ret = marker_trav_parent (&local->loc);

        if (ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "Error occurred "
                        "while traversing to the parent, stopping marker");
                done = 1;
                goto out;
        }

        ret = mc_start_update_count (frame, this);

out:
        if (done)
                mc_xattrop_done (frame);

        return ret;
}

int32_t
mc_mark_clean (call_frame_t *frame, loc_t *loc)
{
        int32_t         ret     = -1;
        xlator_t        *this   = NULL;

        GF_ASSERT (frame);
        GF_ASSERT (loc);

        this = THIS;

        STACK_WIND (frame, mc_mark_clean_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->removexattr,
                    loc, GF_COUNT_DIRTY_KEY, NULL);

        ret = 0;

        return ret;
}

int
mc_xattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, dict_t *xattr,
                dict_t *xdata)
{
        int32_t         ret   = -1;
        marker_local_t  *local = NULL;

        local = (marker_local_t*) frame->local;

        if (op_ret == -1 && op_errno == ENOSPC) {
                //marker_error_handler (this, local, op_errno);
                goto out;
        }

        ret = mc_mark_clean (frame, &local->loc);

out:
        return ret;
}
int32_t
mc_xattrop (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
            int32_t op_errno, dict_t *xdata)
{
        int32_t         ret     = -1;
        dict_t          *dict  = NULL;
        marker_local_t  *local = NULL;

        if (!this)
                goto out;

        if (op_ret) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "marking dirty xattr failed: %s",
                        strerror(op_errno));
                //continue as we need to proceed till root
        }

        local = (marker_local_t*) frame->local;

        if (!local)
                goto out;

        dict = dict_new ();
        if (!dict)
                goto out;

        ret = dict_set_int64 (dict, "trusted.glusterfs.count",
                              local->count_modify_value);
        if (ret) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to set marker xattr (%s)", local->loc.path);
                goto out;
        }

        STACK_WIND (frame, mc_xattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->xattrop, &local->loc,
                    GF_XATTROP_ADD_VALUE, dict, NULL);

        ret = 0;

out:
        return ret;


}

int32_t
mc_mark_dirty (call_frame_t *frame, loc_t *loc)
{
        int32_t         ret     = -1;
        dict_t          *dict   = NULL;
        xlator_t        *this   = NULL;

        GF_ASSERT (frame);

        this = THIS;

        dict = dict_new ();
        if (!dict) {
                ret = -1;
                goto err;
        }

        ret = dict_set_int8 (dict, GF_COUNT_DIRTY_KEY, 1);
        if (ret == -1)
                goto err;

        GF_UUID_ASSERT (loc->gfid);

        STACK_WIND (frame, mc_xattrop,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->setxattr,
                    loc, dict, 0, NULL);

        ret = 0;
err:

        if (dict)
                dict_unref (dict);

        return ret;
}


int32_t
mc_start_update_count (call_frame_t *frame, xlator_t *this)
{
        int32_t          ret   = -1;
        marker_local_t  *local = NULL;

        if (!frame || !this)
                goto out;

        local = (marker_local_t*) frame->local;

        if (!local)
                goto out;

        if (local->loc.inode && uuid_is_null (local->loc.gfid))
                uuid_copy (local->loc.gfid, local->loc.inode->gfid);

        GF_UUID_ASSERT (local->loc.gfid);

        ret = mc_mark_dirty (frame, &local->loc);

out:
        return ret;
}

/*
 *
 * The process of updating counts in the directory hierarchy
 * includes the following steps:
 *     (i)   mark the parent as dirty
 *     (ii)  update the parent count and its contribution recursively
 *           upwards
 *     (iii) remove the dirty tag from parent
 *
 * A heal operation is trigerred if the dirty tag is observed on a directory.
 */

/* TODO: Replace local_t with loc_t */

int32_t
mc_update_count (marker_local_t *local, int count)
{
        int32_t         ret     = -1;
        call_frame_t    *frame  = NULL;
        xlator_t        *this   = NULL;

        this = THIS;
        GF_VALIDATE_OR_GOTO ("marker", this, out);
        GF_VALIDATE_OR_GOTO (this->name, local, out);

        marker_local_ref (local);
        local->count_modify_value = count;

        ret = mc_create_frame (local, &frame);
        if (ret)
                goto out;

        ret =  mc_start_update_count (frame, this);
out:
        return ret;
}

#if 0
/* Healing related code */
int32_t
mq_inspect_directory_xattr (xlator_t *this,
                            loc_t *loc,
                            dict_t *dict,
                            struct iatt *buf)
{
        int32_t               ret                 = 0;
        int8_t                dirty               = -1;
        int64_t              *size                = NULL, size_int = 0;
        int64_t              *contri              = NULL, contri_int = 0;
        char                  contri_key [512]    = {0, };
        gf_boolean_t          not_root            = _gf_false;
        quota_inode_ctx_t    *ctx                 = NULL;
        inode_contribution_t *contribution        = NULL;

        ret = mq_inode_ctx_get (loc->inode, this, &ctx);
        if (ret < 0) {
                ctx = mq_inode_ctx_new (loc->inode, this);
                if (ctx == NULL) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "mq_inode_ctx_new failed");
                        ret = -1;
                        goto err;
                }
        }

        if (strcmp (loc->path, "/") != 0) {
                contribution = mq_add_new_contribution_node (this, ctx, loc);
                if (contribution == NULL) {
                        if (!uuid_is_null (loc->inode->gfid))
                                gf_log (this->name, GF_LOG_WARNING,
                                        "cannot add a new contribution node");
                        ret = -1;
                        goto err;
                }
        }

        ret = dict_get_bin (dict, QUOTA_SIZE_KEY, (void **) &size);
        if (ret < 0)
                goto out;

        ret = dict_get_int8 (dict, QUOTA_DIRTY_KEY, &dirty);
        if (ret < 0)
                goto out;

        if (strcmp (loc->path, "/") != 0) {
                not_root = _gf_true;

                GET_CONTRI_KEY (contri_key, contribution->gfid, ret);
                if (ret < 0)
                        goto out;

                ret = dict_get_bin (dict, contri_key, (void **) &contri);
                if (ret < 0)
                        goto out;

                LOCK (&contribution->lock);
                {
                        contribution->contribution = ntoh64 (*contri);
                        contri_int = contribution->contribution;
                }
                UNLOCK (&contribution->lock);
        }

        LOCK (&ctx->lock);
        {
                ctx->size = ntoh64 (*size);
                ctx->dirty = dirty;
                size_int = ctx->size;
        }
        UNLOCK (&ctx->lock);

        gf_log (this->name, GF_LOG_DEBUG, "size=%"PRId64
                " contri=%"PRId64, size_int, contri_int);

        if (dirty) {
                ret = mq_update_dirty_inode (this, loc, ctx, contribution);
        }

        if ((!dirty || ret == 0) && (not_root == _gf_true) &&
            (size_int != contri_int)) {
                mq_initiate_quota_txn (this, loc);
        }

        ret = 0;
out:
        if (ret)
                mq_set_inode_xattr (this, loc);
err:
        return ret;
}

int32_t
mc_inspect_file_xattr (xlator_t *this, loc_t *loc,
                       dict_t *dict, struct iatt *buf)
{
        int32_t               ret              = -1;

        if (!this || !dict)
                goto out;

        ret = dict_get_bin (dict, contri_key, (void **) &contri_int);
        if (ret == 0) {
                contri_ptr = (int64_t *)(unsigned long)contri_int;

                LOCK (&contribution->lock);
                {
                        contribution->contribution = ntoh64 (*contri_ptr);
                        contri_int = contribution->contribution;
                }
                UNLOCK (&contribution->lock);

                gf_log (this->name, GF_LOG_DEBUG,
                        "size=%"PRId64 " contri=%"PRId64, size, contri_int);

                if (size != contri_int) {
                        mq_initiate_quota_txn (this, loc);
                }
        } else
                mq_initiate_quota_txn (this, loc);

out:
        return ret;
}

int32_t
mc_xattr_state (xlator_t *this,
                loc_t *loc,
                dict_t *dict,
                struct iatt *buf)
{
        if (!buf)
                goto out;

        if (buf->ia_type == IA_IFREG ||
            buf->ia_type == IA_IFLNK) {
                mc_inspect_file_xattr (this, loc, dict, buf);
        } else if (buf->ia_type == IA_IFDIR)
                mc_inspect_directory_xattr (this, loc, dict, buf);

out:
        return 0;
}
#endif
