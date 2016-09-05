/**
 * 实现头尾可控单向循环链表
 * 用slist_del_head，slist_add_tail函数尤其适合实现队列
 * 移植自linux之list.h，所有更详细说明见linux之list.h，包括各函数的陷阱
 * 本文档中头entry和链表表示的意思一样，常常用头entry表示链表
 * 传入参数若无特殊说明均为指针
 * __XXX为内部接口，调用可能有危险，为不推荐使用的接口
 * XXX__为性能较差的接口，应尽量使用其他接口替代
 *
 * cjpthree@126.com 2014-4-10 Create
 *
 * 使用示例：
 * struct mynode {
 *     struct slist_node slist;
 *     // other members
 * };
 * struct slist_head myslist;
 * struct mynode node1;
 * SINIT_LIST_HEAD(&myslist);
 * slist_add_tail(&(node1.slist), &myslist);
 */
#ifndef _LINUX_SLIST_H_
#define _LINUX_SLIST_H_

/**
 * 头entry结构
 * 文档内slist_head_t和slist_node_t的强制类型转换依赖于next和pptail的顺序，两元素的顺序不能改变，
 * 支持左值强制类型转换的编译器上，允许头entry和普通entry都定义为slist_head_t，
 * 不支持左值强制类型转换的编译器上，用户必须把头entry定义为slist_head_t，普通entry定义为slist_node_t。
 */
typedef struct slist_head {
    struct slist_node *next;    /* 总是指向第一个entry */
    struct slist_node **pptail; /* 总是指向最后一个entry的next域 */
} slist_head_t;

/**
 * entry结构
 */
typedef struct slist_node {
    struct slist_node *next; /* 指向后面的entry */
} slist_node_t;

/**
 * 初始化链表
 */
#define SLIST_HEAD_INIT(name) \
    {(slist_node_t *)&(name), &((name).next)}

/**
 * 定义并初始化链表
 * @name: 链表的标识符
 */
#define SLIST_HEAD(name) \
    slist_head_t (name) = SLIST_HEAD_INIT(name)

/**
 * 初始化链表
 * @head: 需要初始化的链表
 */
#define INIT_SLIST_HEAD(head) \
do { \
    (head)->next = (slist_node_t *)(head); \
    (head)->pptail = &((head)->next); \
} while (0)

/**
 * 初始化entry
 * @node: 需要初始化的entry
 */
#define INIT_SLIST_NODE(s_node) \
    ((s_node)->next = (slist_node_t *)(s_node))

/**
 * 判断是否为空链表，空链表只有头结点
 * @head: the list to test.
 */
#define slist_empty(head) \
    ((head)->next == (slist_node_t *)(head))

/**
 * 判断链表是否只有一个entry
 * @head: the list to test.
 */
#define slist_is_singular(head) \
    (!slist_empty(head) && ((head)->pptail == &(head)->next->next))

/**
 * 获取链表最后一个entry
 * @head: the list to test.
 */
#define slist_get_last(head) \
    slist_entry((head)->pptail, slist_node_t, next)

/**
 * 获取链表第一个entry
 * @head: the list to test.
 */
#define slist_get_first(head) \
    ((head)->next)

/**
 * 在entry后面插入一个新的entry
 * @new_entry:  要插入的entry
 * @prev_entry: 前面那个entry
 */
#define __slist_add(new_entry, prev_entry) \
do { \
    (new_entry)->next = (prev_entry)->next; \
    (prev_entry)->next = (slist_node_t *)(new_entry); \
} while (0)

/**
 * 头插法插入新entry
 * @new_entry:  new entry to be added
 * @head:       头entry
 */
#define slist_add_head(new_entry, head) \
do { \
    if (slist_empty(head)) { \
        (head)->pptail = &(new_entry)->next; \
    } \
    __slist_add((new_entry), (head)); \
} while (0)

/**
 * 尾插法插入新entry
 * @new_entry:  new entry to be added
 * @head:       头entry
 */

#define slist_add_tail(new_entry, head) \
do { \
    __slist_add((new_entry), slist_get_last(head));  \
   (head)->pptail = &(new_entry)->next;  \
} while (0)

/**
* 在后面插入新entry
* @new_entry:  new entry to be added
* @prev_entry: 插入位置前一个entry
*/
#define slist_add_after(new_entry, prev_entry, head) \
do { \
    if ((slist_node_t *)(prev_entry) == slist_get_last(head)) { \
        (head)->pptail = &(new_entry)->next;  \
    } \
    __slist_add((new_entry), (prev_entry)); \
} while (0)

/**
 * 在前面插入新entry
 * @new_entry:  需要插入的entry
 * @next_entry: 将会插入此entry前面
 * @head:       头entry
 *
 * 将会链表头开始寻找entry的前驱，找到后插入entry
 * 耗时较多，不推荐
 */
#define slist_add_before__(new_entry, next_entry, head) \
do {  \
    slist_node_t *pos_prev; \
    if ((slist_node_t *)(next_entry) == (slist_node_t *)(head)) { \
        slist_add_head((new_entry), (head)); \
    } else { \
        slist_for_each(pos_prev, (head)) { \
            if (pos_prev == (slist_node_t *)(next_entry)) { \
                slist_add_after((new_entry), pos_prev, (head)); \
                break; \
            } \
        } \
    } \
} while (0)

/**
 * 从链表删除prev_entry后面的entry
 * @prev_entry: 需要删除的entry的前面那个entry
 */
#define __slist_del(prev_entry) \
    ((prev_entry)->next = (prev_entry)->next->next)

/**
 * 删除链表的第一个entry
 * @head: 链表头entry
 *
 * 性能好，推荐使用
 */
#define slist_del_head(head) \
do { \
    if (slist_is_singular(head)) { \
        (head)->pptail = &(head)->next; \
    } \
    __slist_del(head); \
} while (0)

/**
 * 删除链表的最后一个entry
 * @head: 链表头entry
 *
 * 性能低的函数，不推荐使用
 */
#define slist_del_tail__(head) \
do { \
    slist_node_t *pos_prev; \
    if (slist_is_singular(head)) { \
        (head)->pptail = &(head)->next; \
        __slist_del(head); \
    } else { \
        slist_for_each(pos_prev, (head)) { \
            if (pos_prev->next == slist_get_last(head)) { \
                (head)->pptail = &pos_prev->next; \
                __slist_del(pos_prev); \
                break; \
            } \
        } \
    } \
} while (0)

/**
 * 删除后面的一个entry
 * @prev_entry: 要删除的entry的前面一个entry
 *
 * 性能好，推荐使用
 */
#define slist_del_after(prev_entry, head) \
do { \
    if ((slist_node_t *)((prev_entry)->next) == slist_get_last(head)) { \
        (head)->pptail = &(prev_entry)->next; \
    } \
    ((prev_entry)->next != (slist_node_t *)(head)) && __slist_del(prev_entry); \
} while (0)

/**
 * 删除当前entry
 * @entry:  需要删除的entry
 * @head:   头entry
 *
 * 将会链表头开始寻找entry的前驱，找到后删除entry
 * 耗时较多，不推荐
 */
#define slist_del__(entry, head) \
do {  \
    slist_node_t *pos_prev; \
    if ((head)->next == (slist_node_t *)(entry)) { \
        (head)->pptail = &(head)->next; \
        __slist_del(head); \
    } else { \
        slist_for_each(pos_prev, (head)) { \
            if (pos_prev->next == (slist_node_t *)(entry)) { \
                slist_del_after(pos_prev, (head)); \
                break; \
            } \
        } \
    } \
} while (0)

/**
 * 获取包含该entry的结构体指针
 * @entry:   包含在结构体中的entry
 * @type:    要获取的结构体的类型
 * @member:  entry在结构体中的标识符
 */
#define slist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/**
 * 遍历链表，不可在遍历中修改链表
 * @pos:    遍历中作游标的entry
 * @head:   the head of your list.
 */
#define slist_for_each(pos, head) \
    for ((pos) = (slist_node_t *)((head)->next); \
        (pos) != (slist_node_t *)(head); \
        (pos) = (slist_node_t *)((pos)->next))

/**
 * 安全地遍历链表，支持遍历中删除链表，可修改pos，不可修改prev
 * @pos:        遍历中作游标的entry
 * @pos_prev:   总是在pos前面的那个entry
 * @head:       the head for your list.
 */
#define slist_for_each_safe(pos_prev, pos, head) \
    for ((pos_prev) = (slist_node_t *)(head), \
        (pos) = (slist_node_t *)((head)->next); \
        (pos) != (slist_node_t *)(head); \
        ((slist_node_t *)((pos_prev)->next) == (slist_node_t *)(pos)) ? \
        ((pos) = (slist_node_t *)((pos)->next), \
        (pos_prev) = (slist_node_t *)((pos_prev)->next)) : \
        ((pos) = (slist_node_t *)((pos_prev)->next)))

#endif /* _LINUX_SLIST_H_ */
