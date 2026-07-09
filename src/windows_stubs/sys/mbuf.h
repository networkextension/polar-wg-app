/* FreeBSD sys/mbuf.h -> Windows userspace stub: single-segment flat buffer */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct mbuf {
    uint8_t  *m_data;
    int       m_len;
    struct {
        int   len;
    } m_pkthdr;
    size_t    _cap;
};

static __inline struct mbuf *
m_devget(const void *data, int len)
{
    struct mbuf *m = (struct mbuf *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->m_data = (uint8_t *)malloc((size_t)len + 64);
    if (!m->m_data) { free(m); return NULL; }
    m->_cap = (size_t)len + 64;
    memcpy(m->m_data, data, (size_t)len);
    m->m_len         = len;
    m->m_pkthdr.len  = len;
    return m;
}

static __inline void
m_freem(struct mbuf *m)
{
    if (m) { free(m->m_data); free(m); }
}

static __inline int
m_append(struct mbuf *m, int cnt, const void *cp)
{
    size_t need = (size_t)(m->m_len + cnt);
    if (need > m->_cap) {
        size_t newcap = need + 64;
        uint8_t *nb = (uint8_t *)realloc(m->m_data, newcap);
        if (!nb) return 0;
        m->m_data = nb;
        m->_cap   = newcap;
    }
    memcpy(m->m_data + m->m_len, cp, (size_t)cnt);
    m->m_len        += cnt;
    m->m_pkthdr.len += cnt;
    return 1;
}

static __inline void
m_adj(struct mbuf *m, int len)
{
    if (len >= 0) {
        if (len > m->m_len) len = m->m_len;
        m->m_data       += len;
        m->m_len        -= len;
        m->m_pkthdr.len -= len;
    } else {
        int trim = -len;
        if (trim > m->m_len) trim = m->m_len;
        m->m_len        -= trim;
        m->m_pkthdr.len -= trim;
    }
}
