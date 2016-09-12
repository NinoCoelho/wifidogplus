/**
 * 实现双向循环链表
 * 移植自linux之list.h，所有更详细说明见linux之list.h，包括各函数的陷阱
 * 本文档中头entry和链表表示的意思一样，常常用头entry表示链表
 * 遍历函数无_entry一律遍历entry，有_entry一律遍历节点
 * 传入参数若无特殊说明均为指针
 *
 * cjpthree@126.com 2011-4-7 Create
 * v1: 2014-4-10 修改为更通用的形式，去除所有inline函数，实现为宏，去除typeof，依赖用户传入type
 *
 * 使用示例:
 * struct mynode {
 *     struct dlist_head dlist;
 *     // other members
 * };
 * struct dlist_head mydlist;
 * struct mynode node1;
 * INIT_DLIST_HEAD(&mydlist);
 * dlist_add(&(node1.dlist), &mydlist);
 */

#ifndef _LINUX_DLIST_H_
#define _LINUX_DLIST_H_

#include <stdio.h>

#define DLIST_POISON1 NULL
#define DLIST_POISON2 NULL

#ifndef offsetof
#define offsetof(type, member) \
    ((unsigned long)(&((type *)0)->member))
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *) ((char *)(ptr) - offsetof(type, member)))
#endif

/**
 * 若系统支持预缓存prefetch，定义此宏，打开预缓存，理论上可以提高速度
 */
//#define SUPPORT_PREFETCH
#ifndef SUPPORT_PREFETCH
#undef prefetch
#define prefetch
#endif

/**
 * 双向循环链表结构，称之为entry，嵌入节点中使用。链表有头entry
 *
 * 注意: Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */
typedef struct dlist_head {
    struct dlist_head *next; /* 指向后面的entry */
    struct dlist_head *prev; /* 指向前面的entry */
} dlist_head_t;

/**
 * 初始化链表
 * @name: 链表的标识符
 *
 * 注意：name为链表标识符，并非指针，本文档出现的head = &name
 */
#define DLIST_HEAD_INIT(name) \
    {&(name), &(name)}

/**
 * 定义并初始化链表
 * @name: 链表的标识符
 */
#define DLIST_HEAD(name) \
    dlist_head_t (name) = DLIST_HEAD_INIT(name)

/**
 * 初始化链表
 * @head: 需要初始化的链表
 */
#define INIT_DLIST_HEAD(head) \
do { \
    (head)->next = (head); \
    (head)->prev = (head); \
} while (0)

/**
 * 在两个连续的entry间插入一个新的entry
 * @new_entry: 要插入的entry
 * @prev_entry: 连续的entry的前面那个
 * @next_entry: 连续的entry的后面那个
 *
 * 现在的实现dlist_add_tail需要临时变量，假如后面两句位置变换了，则dlist_add需要创建临时变量
 * 故对dlist未足够了解不要尝试调用此函数或者修改此函数
 */
#define __dlist_add(new_entry, prev_entry, next_entry) \
do { \
    (next_entry)->prev = (new_entry); \
    (new_entry)->next = (next_entry); \
    (new_entry)->prev = (prev_entry); \
    (prev_entry)->next = (new_entry); \
} while (0)

/**
 * 头插法插入新entry
 * @new_entry: new entry to be added
 * @head: 头entry
 */
#define dlist_add(new_entry, head) \
    __dlist_add((new_entry), (head), (head)->next);

/**
 * 尾插法插入新entry
 * @new_entry: new entry to be added
 * @head: dlist head to add it before
 */
#define dlist_add_tail(new_entry, head) \
do { \
    struct dlist_head *prev = (head)->prev; \
    __dlist_add((new_entry), prev, (head)); \
} while (0)

/**
 * 从链表删除prev_entry和next_entry之间的entry
 * @prev_entry: 需要删除的entry的前面那个entry
 * @next_entry: 需要删除的entry的后面那个entry
 *
 * This is only for internal dlist manipulation where we know
 * the prev/next entries already!
 */
#define __dlist_del(prev_entry, next_entry) \
do { \
    (next_entry)->prev = (prev_entry); \
    (prev_entry)->next = (next_entry); \
} while (0)

/**
 * 删除一个entry
 * @entry: 要删除的entry
 *
 * Note: dlist_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
#define dlist_del(entry) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    (entry)->next = DLIST_POISON1; \
    (entry)->prev = DLIST_POISON2; \
} while (0)

/**
 * 判断是否为空链表，空链表只有头结点
 * @head: the dlist to test.
 */
#define dlist_empty(head) \
    ((head)->next == (head))

/**
 * 更小心地判断链表是否为空
 * @head: the dlist to test
 *
 * Description:
 * tests whether a dlist is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using dlist_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the dlist entry is dlist_del_init(). Eg. it cannot be used
 * if another CPU could re-dlist_add() it.
 */
#define dlist_empty_careful(head) \
    ((head)->next == (head)) && ((head)->next == (head)->prev)

/**
 * 获取包含该entry的结构体指针
 * @entry:   包含在结构体中的entry
 * @type:    要获取的结构体的类型
 * @member:  entry在结构体中的标识符
 *
 * old code: container_of(entry, type, member)
 */
#define dlist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/**
 * 遍历链表，不可在遍历中修改链表
 * @pos:    遍历中作游标的entry
 * @head:   the head of your dlist.
 */
#define dlist_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/**
 * 安全地遍历链表，支持遍历中修改链表
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @pos_tmp:    作为临时存贮空间的entry，总会在pos前面试探一步
 * @head:       the head for your dlist.
 */
#define dlist_for_each_safe(pos, pos_tmp, head) \
    for ((pos) = (head)->next, (pos_tmp) = (pos)->next; \
        (pos) != (head); \
        (pos) = (pos_tmp), (pos_tmp) = (pos)->next)

/**
 * 循着链表遍历节点，不可在遍历中修改链表
 * @pos:        包含entry的节点结构，用来做游标节点
 * @head:       the head of your dlist.
 * @member:     在节点结构中entry的标识符
 */
#define dlist_for_each_entry(pos, head, type, member)  \
    for ((pos) = dlist_entry((head)->next, type, member);  \
         &(pos)->member != (head); \
         (pos) = dlist_entry((pos)->member.next, type, member))

/**
 * 以安全的方式循着链表遍历节点，支持遍历中修改链表
 * @pos:        the type * to use as a loop cursor.
 * @pos_tmp:       作为临时存贮空间的节点，总会在pos前面试探一步
 * @head:       the head for your dlist.
 * @member:     the name of the dlist_struct within the struct.
 */
#define dlist_for_each_entry_safe(pos, pos_tmp, head, type, member)     \
    for ((pos) = dlist_entry((head)->next, type, member),    \
        (pos_tmp) = dlist_entry((pos)->member.next, type, member); \
         &(pos)->member != (head);                     \
         (pos) = (pos_tmp), \
         (pos_tmp) = dlist_entry((pos_tmp)->member.next, type, member))

/**
 * 用新的entry代替旧的entry在链表中的位置
 * @old_entry : the element to be replaced
 * @new_entry : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
#define dlist_replace(old_entry, new_entry) \
do { \
    (new_entry)->next = (old_entry)->next; \
    (new_entry)->next->prev = (new_entry); \
    (new_entry)->prev = (old_entry)->prev; \
    (new_entry)->prev->next = (new_entry); \
} while (0)

/**
 * 用新的entry代替旧的entry在链表中的位置，并重新初始化旧的entry
 * @old_entry : the element to be replaced
 * @new_entry : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
#define dlist_replace_init(old_entry, new_entry) \
do { \
    dlist_replace((old_entry), (new_entry)); \
    INIT_DLIST_HEAD(old_entry); \
} while (0)

/**
 * 删除entry并重新初始化它
 * @entry: the element to delete from the dlist.
 */
#define dlist_del_init(entry) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    INIT_DLIST_HEAD(entry); \
} while (0)

/**
 * 把一个entry从一个链表中删除，并用头插法加入另一个链表
 * @entry:  the entry to move
 * @head:   the head that will precede our entry
 */
#define dlist_move(entry, head) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    dlist_add((entry), (head)); \
} while (0)

/**
 * 把一个entry从一个链表中删除，并用尾插法加入另一个链表
 * @dlist: the entry to move
 * @head: the head that will follow our entry
 */
#define dlist_move_tail(entry, head) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    dlist_add_tail((entry), (head)); \
} while (0)

/**
 * 判断一个entry是否是表尾
 * @entry: the entry to test
 * @head: the head of the dlist
 */
#define dlist_is_last(entry, head) \
    ((entry)->next == head)

/**
 * 获取链表的第一个节点
 * @head:    the dlist head to take the element from.
 * @type:    the type of the struct this is embedded in.
 * @member:  the name of the dlist_struct within the struct.
 */
#define dlist_first_entry(head, type, member) \
    (dlist_empty(head) ? NULL : dlist_entry((head)->next, type, member))

/**
 * 获取链表的最后一个节点
 * @head:    the dlist head to take the element from.
 * @type:    the type of the struct this is embedded in.
 * @member:  the name of the dlist_struct within the struct.
 */
#define dlist_last_entry(head, type, member) \
    (dlist_empty(head) ? NULL : dlist_entry((head)->prev, type, member))

/**
 * 判断链表是否只有一个entry
 * @head: the dlist to test.
 */
#define dlist_is_singular(head) \
    (!dlist_empty(head) && ((head)->next == (head)->prev))

/**
 * 把原先head链表中的第一个entry到入参entry之间的entry移动到new_head链表
 * @head:       原链表
 * @entry:      需要被砍掉的最后一个entry，应是head链表中的一个entry
 * @new_head:   接收被砍掉的entry的链表，应该是一个空链表，否则链表数据丢失出错
 */
#define __dlist_cut_position(new_head, head, entry) \
do { \
    struct dlist_head *new_first = entry->next; \
    (new_head)->next = (head)->next; \
    (new_head)->next->prev = (new_head); \
    (new_head)->prev = (entry); \
    (entry)->next = (new_head); \
    (head)->next = new_first; \
    new_first->prev = (head); \
} while (0)

/**
 * 把表分解成两个表，把原先head链表中的第一个entry到入参entry之间的entry移动到new_head链表
 * @new_head:   a new dlist to add all removed entries
 * @head:       a dlist with entries
 * @entry:      an entry within head, could be the head itself
 *    and if so we won't cut the dlist
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @dlist. You should
 * pass on @entry an element you know is on @head. @dlist
 * should be an empty dlist or a dlist you do not care about
 * losing its data.
 */
#define dlist_cut_position(new_head, head, entry) \
do { \
    if (dlist_empty(head)) { \
        /* retrun here */ \
    } else if (dlist_is_singular(head) && ((head)->next != (entry) && (head) != (entry))) { \
        /* retrun here */ \
    } else if ((entry) == (head)) { \
        INIT_DLIST_HEAD(new_head); \
    } else { \
        __dlist_cut_position((new_head), (head), (entry)); \
    } \
} while (0)

/**
 * 连接两个链表，一个链表插到另一个链表的head_prev和head_next之间
 * @new_head:   需要插入的链表
 * @head_prev:  接收新链表的位置前一个entry
 * @head_next:  接收新链表的位置后一个entry
 */
#define __dlist_splice(new_head, head_prev, head_next_) \
do { \
    struct dlist_head *first = (new_head)->next; \
    struct dlist_head *last = (new_head)->prev; \
    struct dlist_head *head_next = head_next_; \
    first->prev = (head_prev); \
    (head_prev)->next = first; \
    last->next = (head_next); \
    (head_next)->prev = last; \
} while (0)

/**
 * 合并两个链表，一个链表插到另一个链表的头部
 * @new_head:   需要插入的链表
 * @head:       被插入的链表，将形成新的更长的链表
 */
#define dlist_splice(new_head, head) \
do { \
    if (!dlist_empty(new_head)) { \
        __dlist_splice((new_head), (head), head_next); \
    } \
} while (0)

/**
 * 连接两个链表，一个链表插到另一个链表的尾部
 * @new_head:   the new dlist to add.
 * @head:       the place to add it in the first dlist.
 */
#define dlist_splice_tail(new_head, head) \
do { \
    if (!dlist_empty(new_head)) { \
        __dlist_splice((new_head), (head)->prev, (head)); \
    } \
} while (0)

/**
 * 头插法连接两个链表，并重新初始化变空的链表
 * @new_head:   the new dlist to add.
 * @head:       the place to add it in the first dlist.
 *
 * The dlist at @dlist is reinitialised
 */
#define dlist_splice_init(new_head, head) \
do { \
    if (!dlist_empty(new_head)) { \
        __dlist_splice((new_head), head, (head)->next); \
        INIT_DLIST_HEAD(new_head); \
    } \
} while (0)

/**
 * 尾插法连接两个链表，并重新初始化变空的链表
 * @dlist:       the new dlist to add.
 * @head:       the place to add it in the first dlist.
 *
 * Each of the dlists is a queue.
 * The dlist at @dlist is reinitialised
 */
#define dlist_splice_tail_init(new_head, head) \
do { \
    if (!dlist_empty(new_head)) { \
        __dlist_splice((new_head), (head)->prev, head); \
        INIT_DLIST_HEAD(new_head); \
    } \
} while (0)

/**
 * 遍历链表，不可在遍历中修改链表
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @head:       the head for your dlist.
 *
 * This variant differs from dlist_for_each() in that it's the
 * simplest possible dlist iteration code, no prefetching is done.
 * Use this for code that knows the dlist to be very short (empty
 * or 1 entry) most of the time.
 *
 * 此文档中与前面的__dlist_for_each()完全一样，仅为保留接口
 */
#define __dlist_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/**
 * 反向遍历链表，不可遍历中修改链表
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @head:       the head for your dlist.
 */
#define dlist_for_each_prev(pos, head) \
    for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

/**
 * 安全地反向遍历链表，支持遍历中修改链表
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @pos_tmp:    another &struct dlist_head to use as temporary storage
 * @head:       the head for your dlist.
 */
#define dlist_for_each_prev_safe(pos, pos_tmp, head) \
    for ((pos) = (head)->prev, (pos_tmp) = (pos)->prev; \
         (pos) != (head); \
         (pos) = (pos_tmp), (pos_tmp) = (pos)->prev)

/**
 * 循着链表反向遍历节点，不可在遍历中修改链表
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your dlist.
 * @type:   the type of pos
 * @member: the name of the dlist_struct within the struct.
 */
#define dlist_for_each_entry_reverse(pos, head, type, member)  \
    for ((pos) = dlist_entry((head)->prev, type, member); \
         &(pos)->member != (head);  \
         (pos) = dlist_entry((pos)->member.prev, type, member))

/**
 * 准备一个节点，可作为dlist_for_each_entry_continue等函数的入参pos
 * @pos:    the type * to use as a start point
 * @head:   the head of the dlist
 * @type:   the type of pos
 * @member: the name of the dlist_struct within the struct.
 *
 * Prepares a pos entry for use as a start point in dlist_for_each_entry_continue().
 */
#define dlist_prepare_entry(pos, head, type, member) \
    ((pos) ? (pos) : dlist_entry((head), type, member))

/**
 * 把pos作为头结点继续遍历链表节点，即从pos的下一个位置开始遍历
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your dlist.
 * @type:   the type of pos
 * @member: the name of the dlist_struct within the struct.
 *
 * Continue to iterate over dlist of given type, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue(pos, head, type, member) \
    for ((pos) = dlist_entry((pos)->member.next, type, member); \
         &(pos)->member != (head); \
         (pos) = dlist_entry((pos)->member.next, type, member))

/**
 * 把pos作为头结点继续反向遍历链表节点
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your dlist.
 * @type:       the type of pos
 * @member:     the name of the dlist_struct within the struct.
 *
 * Start to iterate over dlist of given type backwards, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue_reverse(pos, head, type, member)        \
    for ((pos) = dlist_entry((pos)->member.prev, type, member);    \
         &(pos)->member != (head);    \
         (pos) = dlist_entry((pos)->member.prev, type, member))

/**
 * 从pos位置起继续遍历节点
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your dlist.
 @ @type:       the type of pos
 * @member:     the name of the dlist_struct within the struct.
 *
 * Iterate over dlist of given type, continuing from current position.
 */
#define dlist_for_each_entry_from(pos, head, type, member)             \
    for (; &(pos)->member != (head);    \
         (pos) = dlist_entry((pos)->member.next, type, member))

/**
 * 把pos作为头结点以安全的方式继续遍历链表节点，即从pos的下一个位置开始遍历
 * @pos:        the type * to use as a loop cursor.
 * @pos_tmp:    another type * to use as temporary storage
 * @head:       the head for your dlist.
 * @type:       the type of pos
 * @member:     the name of the dlist_struct within the struct.
 *
 * Iterate over dlist of given type, continuing after current point,
 * safe against removal of dlist entry.
 */
#define dlist_for_each_entry_safe_continue(pos, pos_tmp, head, type, member)     \
    for ((pos) = dlist_entry((pos)->member.next, type, member),         \
        (pos_tmp) = dlist_entry((pos)->member.next, type, member);        \
         &(pos)->member != (head);  \
         (pos) = (pos_tmp), \
         (pos_tmp) = dlist_entry((pos_tmp)->member.next, type, member))

/**
 * 从pos位置起以安全的方式继续遍历节点
 * @pos:        the type * to use as a loop cursor.
 * @pos_tmp:    another type * to use as temporary storage
 * @head:       the head for your dlist.
 * @type:       the type of pos
 * @member:     the name of the dlist_struct within the struct.
 *
 * Iterate over dlist of given type from current point, safe against
 * removal of dlist entry.
 */
#define dlist_for_each_entry_safe_from(pos, pos_tmp, head, type, member)             \
    for ((pos_tmp) = dlist_entry((pos)->member.next, type, member);        \
         &(pos)->member != (head);   \
         (pos) = (pos_tmp), \
         (pos_tmp) = dlist_entry((pos_tmp)->member.next, type, member))

/**
 * 以安全的方式反向遍历节点
 * @pos:        the type * to use as a loop cursor.
 * @pos_tmp:    another type * to use as temporary storage
 * @head:       the head for your dlist.
 * @type:       the type of pos
 * @member:     the name of the dlist_struct within the struct.
 *
 * Iterate backwards over dlist of given type, safe against removal
 * of dlist entry.
 */
#define dlist_for_each_entry_safe_reverse(pos, pos_tmp, head, type, member)        \
    for ((pos) = dlist_entry((head)->prev, type, member),    \
        (pos_tmp) = dlist_entry((pos)->member.prev, type, member);    \
         &(pos)->member != (head);                     \
         (pos) = (pos_tmp), \
         (pos_tmp) = dlist_entry((pos_tmp)->member.prev, type, member))

#endif /* _LINUX_DLIST_H_ */

