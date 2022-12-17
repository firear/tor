/**
 * @file cm.h
 * @author your name (you@domain.com)
 * @brief connection manager
 * @version 0.1
 * @date 2022-11-10
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef __CM_H__
#define __CM_H__

#include "hmutex.h"
#include "tor.h"
#include "rbtree.h"

typedef struct cm_s {
    struct rb_root rb_root;
    hmutex_t mutex;
} cm_t;

typedef struct cm_entry_s {
    struct rb_node rb_node;
    uint32_t cid; // key
    // val
    tor_t* tun;

} cm_entry_t;

// NOTE: cm_entry_t alloc when cm_get
void cm_entry_free(cm_entry_t* entry);

void cm_init(cm_t* cm);
void cm_cleanup(cm_t* cm);

bool cm_insert(cm_t* cm, cm_entry_t* entry);
// NOTE: just rb_erase, not free
cm_entry_t* cm_remove(cm_t* cm, uint32_t cid);
cm_entry_t* cm_search(cm_t* cm, uint32_t cid);
#define cm_has(cm, cid) (cm_search(cm, cid) != NULL)

// cm_search + malloc + cm_insert
cm_entry_t* cm_get(cm_t* cm, uint32_t cid);
// cm_remove + free
void cm_del(cm_t* cm, uint32_t cid);

// cm_get(&io->cm, io->peeraddr)
// cm_entry_t* hio_get_cm(io_t* io);

void for_each(cm_t* cm, void (*cb)(tor_t* tun, void* user), void* user);

#endif // __CM_H__
