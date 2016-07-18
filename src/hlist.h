/**
 * ʵ�������ڹ�ϣ�������
 * ��ֲ��linux֮list.h�����и���ϸ˵����linux֮list.h������������������
 * ���ĵ���ͷentry�������ʾ����˼һ����������ͷentry��ʾ����
 * ����������_entryһ�ɱ���entry����_entryһ�ɱ����ڵ�
 * ���������������˵����Ϊָ��
 *
 * ��ϣ������÷�������˫��ѭ������һ��������ע�Ϳɲο�˫��ѭ������Ķ�Ӧ����
 * �Ա�: ˫��ѭ�������ͷentry�ͱ�Ԫ��entryһ����
 * ����ϣ�����ͷentryֻ��һ��firstָ�룬
 * ��Ԫ��entry��nextָ���˫��ѭ������һ����
 * pprevָ��ǰһ��entry��nextָ�룬����ͷentry��ָ����firstָ��
 *
 * cjpthree@126.com 2011-4-7 Create
 * v1: 2014-4-10 �޸�Ϊ��ͨ�õ���ʽ��ȥ������inline������ʵ��Ϊ�꣬ȥ��typeof�������û�����type
 *
 * ʹ��ʾ������ϣͷentry�����û�ά����ÿһ��ɢ�б�ͨ�����ĵ�ά��:
 * struct myhnode {
 *     struct hlist_node hlist;
 *     // other members
 * }
 * struct hlist_head myhlist; // ��һ����ǹ�ϣ��Ԫ�أ�Ҳ��ÿ����ı�ͷ
 * struct myhnode hnode1;
 * INIT_HLIST_HEAD(&myhlist);
 * hlist_add_head(&(hnode1.hlist), &myhlist);
 */

#ifndef _LINUX_HLIST_H_
#define _LINUX_HLIST_H_

#include <stdio.h>

#define LIST_POISON1 NULL
#define LIST_POISON2 NULL

/**
 * ��ϵͳ֧��Ԥ����prefetch������˺꣬��Ԥ���棬�����Ͽ�������ٶ�
 */
//#define SUPPORT_PREFETCH
#ifndef SUPPORT_PREFETCH
#undef prefetch
#define prefetch
#endif

/**
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

/* entry */
typedef struct hlist_node {
    struct hlist_node *next;    /* ָ����һ��entry */
    struct hlist_node **pprev;  /* ָ����һ��entry��nextָ���ͷentry��firstָ�� */
} hlist_node_t;

/* ͷentry */
typedef struct hlist_head {
    struct hlist_node *first;   /* ָ���һ��entry */
} hlist_head_t;


/**
 * ��ʼ������
 * @name: �����ʶ��
 */
#define HLIST_HEAD_INIT(name) \
    { (name).first = NULL }

/**
 * ���岢��ʼ������
 * @name: �����ʶ��
 */
#define HLIST_HEAD(name) \
    struct hlist_head name = {(name).first = NULL}

/**
 * ��ʼ������
 * @head: ����ͷentry
 */
#define INIT_HLIST_HEAD(head) \
    ((head)->first = NULL)

/**
 * ��ʼ��һ��hash entry
 * @h_node: Ҫ��ʼ����entry
 */
#define INIT_HLIST_NODE(h_node) \
do { \
    (h_node)->next = NULL; \
    (h_node)->pprev = NULL; \
} while (0)

/**
 * �ж�h_node�Ƿ�û�м����ϣ��
 */
#define hlist_unhashed(h_node) \
    (!(h_node)->pprev)

/**
 * �ж������Ƿ�Ϊ��
 */
#define hlist_empty(head) \
    (!(head)->first)

/**
 * ��������ɾ��һ��entry
 */
#define __hlist_del(h_node) \
do { \
    *((h_node)->pprev) = (h_node)->next; \
    if ((h_node)->next) \
        (h_node)->next->pprev = (h_node)->pprev; \
} while (0)

/**
 * ɾ��һ��entry
 */
#define hlist_del(h_node) \
do { \
    __hlist_del(h_node); \
    (h_node)->next = LIST_POISON1; \
    (h_node)->pprev = LIST_POISON2; \
} while (0)

/**
 * ɾ��entry�����³�ʼ��
 */
#define hlist_del_init(h_node) \
do { \
    if (!hlist_unhashed(h_node)) { \
        __hlist_del(h_node); \
        INIT_HLIST_NODE(h_node); \
    } \
} while (0)

/**
 * ͷ�巨����entry
 * @h_node: Ҫ�����entry
 * @head:   ����ͷentry
 */
#define hlist_add_head(h_node, head) \
do { \
    (h_node)->next = (head)->first; \
    if ((head)->first) { \
        (head)->first->pprev = &(h_node)->next; \
    } \
    (head)->first = (h_node); \
    (h_node)->pprev = &(head)->first; \
} while (0)

/**
 * ��һ��entry���뵽��һentry֮ǰ
 * @h_node:     Ҫ�����entry
 * @next_node:  ho_node��������֮ǰ
 *
 * next_node must be != NULL
 */
#define hlist_add_before(h_node, next_node) \
do { \
    (h_node)->pprev = (next_node)->pprev; \
    (h_node)->next = (next_node); \
    (next_node)->pprev = &(h_node)->next; \
    *((h_node)->pprev) = (h_node); \
} while (0)

/**
 * ��һ��entry���뵽��һentry֮��
 * @h_node:     Ҫ�����entry
 * @befor_node:  ho_node��������֮��
 */
#define hlist_add_after(prev_node, h_node) \
do { \
    (h_node)->next = (prev_node)->next; \
    (prev_node)->next = (h_node); \
    (h_node)->pprev = &(prev_node)->next; \
      \
    if((h_node)->next) { \
        (h_node)->next->pprev  = &(h_node)->next; \
    } \
} while (0)

/**
 * ��һ�������ƶ�����һ��
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
#define hlist_move_list(old_head, new_head) \
do { \
    (new_head)->first = (old_head)->first; \
    if ((new_head)->first) \
        (new_head)->first->pprev = &(new_head)->first; \
    (old_head)->first = NULL; \
} while (0)

/**
 * ��ȡ������entry�Ľṹ��ָ��
 * @entry:   �����ڽṹ���е�entry
 * @type:    Ҫ��ȡ�Ľṹ�������
 * @member:  entry�ڽṹ���еı�ʶ��
 */
#define hlist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/* �������� */
#define hlist_for_each(pos, head) \
    for ((pos) = (head)->first; (pos) && (prefetch((pos)->next), 1); (pos) = (pos)->next)

/* ��ȫ�ر������� */
#define hlist_for_each_safe(pos, pos_tmp, head) \
    for ((pos) = (head)->first; (pos) && ((pos_tmp) = (pos)->next, 1); (pos) = (pos_tmp))

/**
 * hlist_for_each_entry    - iterate over list of given type
 * @tpos:    the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @head:    the head for your list.
 * @member:    the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, type, member) \
    for ((pos) = (head)->first;                     \
        (pos) && (prefetch((pos)->next), 1) &&  \
        ((tpos) = hlist_entry((pos), type, member), 1); \
        (pos) = (pos)->next)

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:       the type * to use as a loop cursor.
 * @pos:        the &struct hlist_node to use as a loop cursor.
 * @pos_tmp:    another &struct hlist_node to use as temporary storage
 * @head:       the head for your list.
 * @type:       the type of tpos
 * @member:     the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_safe(tpos, pos, pos_tmp, head, type, member)  \
    for ((pos) = (head)->first;     \
         (pos) && ((pos_tmp) = (pos)->next, 1) &&  \
        ((tpos) = hlist_entry((pos), type, member), 1); \
         (pos) = (pos_tmp))

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @tpos:   the type * to use as a loop cursor.
 * @pos:    the &struct hlist_node to use as a loop cursor.
 * @type:   the type of tpos
 * @member: the name of the hlist_node within the struct.
 *
 * �ú���tpos��pos����Ҫ�г�ֵ������Ҫ��Ϊ�����α�
 */
#define hlist_for_each_entry_continue(tpos, pos, type, member)   \
    for ((pos) = (pos)->next;                         \
         (pos) && (prefetch((pos)->next), 1)  && \
         ((tpos) = hlist_entry((pos), type, member), 1); \
         (pos) = (pos)->next)

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @tpos:       the type * to use as a loop cursor.
 * @pos:        the &struct hlist_node to use as a loop cursor.
 * @type:       the type of tpos
 * @member:     the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, type, member)   \
    for (; (pos) && (prefetch((pos)->next), 1) &&             \
        ((tpos) = hlist_entry((pos), type, member), 1); \
         (pos) = (pos)->next)

#endif /* _LINUX_HLIST_H_ */

