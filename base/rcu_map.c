#include <base.h>
#include "rcu_map.h"

rcu_map_t *rcu_map_init(rcu_map_t *m, uint32_t buckets, int node_offset,
                        cds_lfht_match_fct match_func, rcu_map_hash_fct hash_func)
{
    struct cds_lfht *ht_map;

    /* 函数分配一个新的哈希表并返回一个指向它的指针，如果错误则返回NULL
       cds_lfht_new(unsigned long init_size, unsigned long min_nr_alloc_buckets, unsigned long max_nr_buckets,
    			    int flags, pthread_attr_t *attr)
       init_size: 指定初始分配的哈希桶的数量，它必须是2的幂
       min_nr_alloc_buckets: 指定哈希桶的最小数目，它也必须是2的幂
       max_nr_buckets:指定哈希桶的最大数目，它必须再次是2的幂。0表示“没有限制”。
       flags：哈希表指定选项。0的值接受默认值，否则可以指定以下标志，如果需要，可以使用按位OR(' | ')来组合
              1). CDS_LFHT_AUTO_RESIZE:自动调整散列表的大小。注意，可以调用cds_lfht_resize()函数来手动调整表的大小。
              2). CDS_LFHT_ACCOUNTING:维护表中节点数量的计数。启用收缩哈希表时需要此标志。因此，CDS_LFHT_AUTO_RESIZE允许哈希表增长，但“CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING”允许哈希表收缩。
       attr: 可选pthread_create()用于调整工作线程大小的线程创建属性(或NULL用于使用默认属性)。
       参考: https://lwn.net/Articles/573432/
     */
    ht_map = cds_lfht_new(buckets, buckets, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
    if (ht_map == NULL) {
        return NULL;
    }

    m->map = ht_map;
    m->match = match_func;
    m->hash = hash_func;
    m->offset = node_offset;
    return m;
}

int rcu_map_destroy(rcu_map_t *m)
{
    return cds_lfht_destroy(m->map, NULL);
}

void rcu_map_add(rcu_map_t *m, void *data, const void *key)
{
    uint32_t hash = m->hash(key);

    cds_lfht_add(m->map, hash, data);
}

void *rcu_map_add_replace(rcu_map_t *m, void *data, const void *key)
{
    uint32_t hash = m->hash(key);
    struct cds_lfht_node *node;

    node = cds_lfht_add_replace(m->map, hash, m->match, key, data + m->offset);
    if (node == NULL) {
        return NULL;
    } else {
        return (void *)node - m->offset;
    }
}

void *rcu_map_lookup(rcu_map_t *m, const void *key)
{
    struct cds_lfht_iter iter;
    struct cds_lfht_node *node;
    uint32_t hash = m->hash(key);

    cds_lfht_lookup(m->map, hash, m->match, key, &iter);
    node = cds_lfht_iter_get_node(&iter);
    if (node == NULL) {
        return NULL;
    }

    return (void *)node - m->offset;
}

void rcu_map_for_each(rcu_map_t *m, rcu_map_for_each_fct each_func, void *args)
{
    struct cds_lfht_iter iter;
    struct cds_lfht_node *node;

    cds_lfht_for_each(m->map, &iter, node) {
        if (unlikely(each_func(node, args))) {
            break;
        }
    }
}

int rcu_map_del(rcu_map_t *m, void *data)
{
    return cds_lfht_del(m->map, (struct cds_lfht_node *)(data + m->offset));
}


