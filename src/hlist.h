/**
 * 实现适用于哈希表的链表
 * 移植自linux之list.h，所有更详细说明见linux之list.h，包括各函数的陷阱
 * 本文档中头entry和链表表示的意思一样，常常用头entry表示链表
 * 遍历函数无_entry一律遍历entry，有_entry一律遍历节点
 * 传入参数若无特殊说明均为指针
 *
 * 哈希链表的用法几乎和双向循环链表一样，函数注释可参考双向循环链表的对应函数
 * 对比: 双向循环链表的头entry和表元素entry一样，
 * 而哈希链表的头entry只有一个first指针，
 * 表元素entry的next指针和双向循环链表一样，
 * pprev指向前一个entry的next指针，对于头entry则指向其first指针
 *
 * cjpthree@126.com 2011-4-7 Create
 * v1: 2014-4-10 修改为更通用的形式，去除所有inline函数，实现为宏，去除typeof，依赖用户传入type
 *
 * 使用示例，哈希头entry表由用户维护，每一个散列表通过本文档维护:
 * struct myhnode {
 *     struct hlist_node hlist;
 *     // other members
 * }
 * struct hlist_head myhlist; // 这一般会是哈希表元素，也是每个表的表头
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
 * 若系统支持预缓存prefetch，定义此宏，打开预缓存，理论上可以提高速度
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
    struct hlist_node *next;    /* 指向下一个entry */
    struct hlist_node **pprev;  /* 指向上一个entry的next指针或头entry的first指针 */
} hlist_node_t;

/* 头entry */
typedef struct hlist_head {
    struct hlist_node *first;   /* 指向第一个entry */
} hlist_head_t;


/**
 * 初始化链表
 * @name: 链表标识符
 */
#define HLIST_HEAD_INIT(name) \
    { (name).first = NULL }

/**
 * 定义并初始化链表
 * @name: 链表标识符
 */
#define HLIST_HEAD(name) \
    struct hlist_head name = {(name).first = NULL}

/**
 * 初始化链表
 * @head: 链表头entry
 */
#define INIT_HLIST_HEAD(head) \
    ((head)->first = NULL)

/**
 * 初始化一个hash entry
 * @h_node: 要初始化的entry
 */
#define INIT_HLIST_NODE(h_node) \
do { \
    (h_node)->next = NULL; \
    (h_node)->pprev = NULL; \
} while (0)

/**
 * 判断h_node是否没有加入哈希表
 */
#define hlist_unhashed(h_node) \
    (!(h_node)->pprev)

/**
 * 判断链表是否为空
 */
#define hlist_empty(head) \
    (!(head)->first)

/**
 * 从链表中删除一个entry
 */
#define __hlist_del(h_node) \
do { \
    *((h_node)->pprev) = (h_node)->next; \
    if ((h_node)->next) \
        (h_node)->next->pprev = (h_node)->pprev; \
} while (0)

/**
 * 删除一个entry
 */
#define hlist_del(h_node) \
do { \
    __hlist_del(h_node); \
    (h_node)->next = LIST_POISON1; \
    (h_node)->pprev = LIST_POISON2; \
} while (0)

/**
 * 删除entry并重新初始化
 */
#define hlist_del_init(h_node) \
do { \
    if (!hlist_unhashed(h_node)) { \
        __hlist_del(h_node); \
        INIT_HLIST_NODE(h_node); \
    } \
} while (0)

/**
 * 头插法插入entry
 * @h_node: 要插入的entry
 * @head:   链表头entry
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
 * 把一个entry插入到另一entry之前
 * @h_node:     要插入的entry
 * @next_node:  ho_node将插入这之前
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
 * 把一个entry插入到另一entry之后
 * @h_node:     要插入的entry
 * @befor_node:  ho_node将插入这之后
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
 * 把一个链表移动到另一个
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
 * 获取包含该entry的结构体指针
 * @entry:   包含在结构体中的entry
 * @type:    要获取的结构体的类型
 * @member:  entry在结构体中的标识符
 */
#define hlist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/* 遍历链表 */
#define hlist_for_each(pos, head) \
    for ((pos) = (head)->first; (pos) && (prefetch((pos)->next), 1); (pos) = (pos)->next)

/* 安全地遍历链表 */
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
 * 该函数tpos和pos都需要有初值，并需要作为遍历游标
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

