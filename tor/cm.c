#include "cm.h"
#include "hbase.h"
#include "io.h"

void cm_entry_free(cm_entry_t* entry)
{
    // #if WITH_KCP
    //     kcp_release(&entry->kcp);
    // #endif
    HV_FREE(entry);
}

void cm_init(cm_t* cm)
{
    // printf("cm init\n");
    cm->rb_root.rb_node = NULL;
    hmutex_init(&cm->mutex);
}

void cm_cleanup(cm_t* cm)
{
    // printf("cm cleaup\n");
    struct rb_node* n = NULL;
    cm_entry_t* e = NULL;
    while ((n = cm->rb_root.rb_node)) {
        e = rb_entry(n, cm_entry_t, rb_node);
        rb_erase(n, &cm->rb_root);
        cm_entry_free(e);
    }
    hmutex_destroy(&cm->mutex);
}

bool cm_insert(cm_t* cm, cm_entry_t* entry)
{
    struct rb_node** n = &cm->rb_root.rb_node;
    struct rb_node* parent = NULL;
    cm_entry_t* e = NULL;
    int cmp = 0;
    bool exists = false;
    while (*n) {
        parent = *n;
        e = rb_entry(*n, cm_entry_t, rb_node);
        cmp = entry->cid - e->cid;
        if (cmp < 0) {
            n = &(*n)->rb_left;
        } else if (cmp > 0) {
            n = &(*n)->rb_right;
        } else {
            exists = true;
            break;
        }
    }

    if (!exists) {
        rb_link_node(&entry->rb_node, parent, n);
        rb_insert_color(&entry->rb_node, &cm->rb_root);
    }
    return !exists;
}

cm_entry_t* cm_search(cm_t* cm, uint32_t cid)
{
    struct rb_node* n = cm->rb_root.rb_node;
    cm_entry_t* e = NULL;
    int cmp = 0;
    bool exists = false;
    while (n) {
        e = rb_entry(n, cm_entry_t, rb_node);
        cmp = cid - e->cid;
        if (cmp < 0) {
            n = n->rb_left;
        } else if (cmp > 0) {
            n = n->rb_right;
        } else {
            exists = true;
            break;
        }
    }
    return exists ? e : NULL;
}

cm_entry_t* cm_remove(cm_t* cm, uint32_t cid)
{
    hmutex_lock(&cm->mutex);
    cm_entry_t* e = cm_search(cm, cid);
    if (e) {
        // printf("cm_remove ");
        // SOCKADDR_PRINT(cid);
        rb_erase(&e->rb_node, &cm->rb_root);
    }
    hmutex_unlock(&cm->mutex);
    return e;
}

cm_entry_t* cm_get(cm_t* cm, uint32_t cid)
{
    hmutex_lock(&cm->mutex);
    struct rb_node** n = &cm->rb_root.rb_node;
    struct rb_node* parent = NULL;
    cm_entry_t* e = NULL;
    int cmp = 0;
    bool exists = false;
    // search
    while (*n) {
        parent = *n;
        e = rb_entry(*n, cm_entry_t, rb_node);
        cmp = cid - e->cid;
        if (cmp < 0) {
            n = &(*n)->rb_left;
        } else if (cmp > 0) {
            n = &(*n)->rb_right;
        } else {
            exists = true;
            break;
        }
    }

    if (!exists) {
        // insert
        // printf("cm_insert ");
        // SOCKADDR_PRINT(addr);
        HV_ALLOC_SIZEOF(e);
        e->cid = cid;
        rb_link_node(&e->rb_node, parent, n);
        rb_insert_color(&e->rb_node, &cm->rb_root);
    }
    hmutex_unlock(&cm->mutex);
    return e;
}

void cm_del(cm_t* cm, uint32_t addr)
{
    hmutex_lock(&cm->mutex);
    cm_entry_t* e = cm_search(cm, addr);
    if (e) {
        // printf("cm_remove ");
        // SOCKADDR_PRINT(addr);
        rb_erase(&e->rb_node, &cm->rb_root);
        cm_entry_free(e);
    }
    hmutex_unlock(&cm->mutex);
}

// cm_entry_t* hio_get_cm(io_t* io)
// {
//     cm_entry_t* cm = cm_get(&io->cm, io->cid);
//     cm->io = io;
//     return cm;
// }

// static void hio_close_cm_event_cb(hevent_t* ev)
// {
//     cm_entry_t* entry = (cm_entry_t*)ev->userdata;
//     cm_del(&entry->io->cm, (uint32_t)&entry->addr);
//     // cm_entry_free(entry);
// }

// int hio_close_cm(io_t* io, uint32_t cid)
// {
//     // NOTE: do cm_del for thread-safe
//     cm_entry_t* entry = cm_get(&io->cm, peeraddr);
//     // NOTE: just cm_remove first, do cm_entry_free async for safe.
//     // cm_entry_t* entry = cm_remove(&io->cm, peeraddr);
//     if (entry) {
//         hevent_t ev;
//         memset(&ev, 0, sizeof(ev));
//         ev.cb = hio_close_cm_event_cb;
//         ev.userdata = entry;
//         ev.priority = HEVENT_HIGH_PRIORITY;
//         hloop_post_event(io->loop, &ev);
//     }
//     return 0;
// }

void for_each(cm_t* manager, void (*cb)(tor_t* tun, void* user), void* user)
{
    struct rb_node* node = rb_first(&manager->rb_root);
    while (node) {
        cm_entry_t* e = rb_entry(node, cm_entry_t, rb_node);
        cb(e->tun, user);
        node = rb_next(node);
    }
}