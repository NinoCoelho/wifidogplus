/**
 * ʵ��˫��ѭ������
 * ��ֲ��linux֮list.h�����и���ϸ˵����linux֮list.h������������������
 * ���ĵ���ͷentry�������ʾ����˼һ����������ͷentry��ʾ����
 * ����������_entryһ�ɱ���entry����_entryһ�ɱ����ڵ�
 * ���������������˵����Ϊָ��
 *
 * cjpthree@126.com 2011-4-7 Create
 * v1: 2014-4-10 �޸�Ϊ��ͨ�õ���ʽ��ȥ������inline������ʵ��Ϊ�꣬ȥ��typeof�������û�����type
 *
 * ʹ��ʾ��:
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
 * ��ϵͳ֧��Ԥ����prefetch������˺꣬��Ԥ���棬�����Ͽ�������ٶ�
 */
//#define SUPPORT_PREFETCH
#ifndef SUPPORT_PREFETCH
#undef prefetch
#define prefetch
#endif

/**
 * ˫��ѭ������ṹ����֮Ϊentry��Ƕ��ڵ���ʹ�á�������ͷentry
 *
 * ע��: Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */
typedef struct dlist_head {
    struct dlist_head *next; /* ָ������entry */
    struct dlist_head *prev; /* ָ��ǰ���entry */
} dlist_head_t;

/**
 * ��ʼ������
 * @name: ����ı�ʶ��
 *
 * ע�⣺nameΪ�����ʶ��������ָ�룬���ĵ����ֵ�head = &name
 */
#define DLIST_HEAD_INIT(name) \
    {&(name), &(name)}

/**
 * ���岢��ʼ������
 * @name: ����ı�ʶ��
 */
#define DLIST_HEAD(name) \
    dlist_head_t (name) = DLIST_HEAD_INIT(name)

/**
 * ��ʼ������
 * @head: ��Ҫ��ʼ��������
 */
#define INIT_DLIST_HEAD(head) \
do { \
    (head)->next = (head); \
    (head)->prev = (head); \
} while (0)

/**
 * ������������entry�����һ���µ�entry
 * @new_entry: Ҫ�����entry
 * @prev_entry: ������entry��ǰ���Ǹ�
 * @next_entry: ������entry�ĺ����Ǹ�
 *
 * ���ڵ�ʵ��dlist_add_tail��Ҫ��ʱ�����������������λ�ñ任�ˣ���dlist_add��Ҫ������ʱ����
 * �ʶ�dlistδ�㹻�˽ⲻҪ���Ե��ô˺��������޸Ĵ˺���
 */
#define __dlist_add(new_entry, prev_entry, next_entry) \
do { \
    (next_entry)->prev = (new_entry); \
    (new_entry)->next = (next_entry); \
    (new_entry)->prev = (prev_entry); \
    (prev_entry)->next = (new_entry); \
} while (0)

/**
 * ͷ�巨������entry
 * @new_entry: new entry to be added
 * @head: ͷentry
 */
#define dlist_add(new_entry, head) \
    __dlist_add((new_entry), (head), (head)->next);

/**
 * β�巨������entry
 * @new_entry: new entry to be added
 * @head: dlist head to add it before
 */
#define dlist_add_tail(new_entry, head) \
do { \
    struct dlist_head *prev = (head)->prev; \
    __dlist_add((new_entry), prev, (head)); \
} while (0)

/**
 * ������ɾ��prev_entry��next_entry֮���entry
 * @prev_entry: ��Ҫɾ����entry��ǰ���Ǹ�entry
 * @next_entry: ��Ҫɾ����entry�ĺ����Ǹ�entry
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
 * ɾ��һ��entry
 * @entry: Ҫɾ����entry
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
 * �ж��Ƿ�Ϊ������������ֻ��ͷ���
 * @head: the dlist to test.
 */
#define dlist_empty(head) \
    ((head)->next == (head))

/**
 * ��С�ĵ��ж������Ƿ�Ϊ��
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
 * ��ȡ������entry�Ľṹ��ָ��
 * @entry:   �����ڽṹ���е�entry
 * @type:    Ҫ��ȡ�Ľṹ�������
 * @member:  entry�ڽṹ���еı�ʶ��
 *
 * old code: container_of(entry, type, member)
 */
#define dlist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/**
 * �������������ڱ������޸�����
 * @pos:    ���������α��entry
 * @head:   the head of your dlist.
 */
#define dlist_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/**
 * ��ȫ�ر�������֧�ֱ������޸�����
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @pos_tmp:    ��Ϊ��ʱ�����ռ��entry���ܻ���posǰ����̽һ��
 * @head:       the head for your dlist.
 */
#define dlist_for_each_safe(pos, pos_tmp, head) \
    for ((pos) = (head)->next, (pos_tmp) = (pos)->next; \
        (pos) != (head); \
        (pos) = (pos_tmp), (pos_tmp) = (pos)->next)

/**
 * ѭ����������ڵ㣬�����ڱ������޸�����
 * @pos:        ����entry�Ľڵ�ṹ���������α�ڵ�
 * @head:       the head of your dlist.
 * @member:     �ڽڵ�ṹ��entry�ı�ʶ��
 */
#define dlist_for_each_entry(pos, head, type, member)  \
    for ((pos) = dlist_entry((head)->next, type, member);  \
         &(pos)->member != (head); \
         (pos) = dlist_entry((pos)->member.next, type, member))

/**
 * �԰�ȫ�ķ�ʽѭ����������ڵ㣬֧�ֱ������޸�����
 * @pos:        the type * to use as a loop cursor.
 * @pos_tmp:       ��Ϊ��ʱ�����ռ�Ľڵ㣬�ܻ���posǰ����̽һ��
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
 * ���µ�entry����ɵ�entry�������е�λ��
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
 * ���µ�entry����ɵ�entry�������е�λ�ã������³�ʼ���ɵ�entry
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
 * ɾ��entry�����³�ʼ����
 * @entry: the element to delete from the dlist.
 */
#define dlist_del_init(entry) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    INIT_DLIST_HEAD(entry); \
} while (0)

/**
 * ��һ��entry��һ��������ɾ��������ͷ�巨������һ������
 * @entry:  the entry to move
 * @head:   the head that will precede our entry
 */
#define dlist_move(entry, head) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    dlist_add((entry), (head)); \
} while (0)

/**
 * ��һ��entry��һ��������ɾ��������β�巨������һ������
 * @dlist: the entry to move
 * @head: the head that will follow our entry
 */
#define dlist_move_tail(entry, head) \
do { \
    __dlist_del((entry)->prev, (entry)->next); \
    dlist_add_tail((entry), (head)); \
} while (0)

/**
 * �ж�һ��entry�Ƿ��Ǳ�β
 * @entry: the entry to test
 * @head: the head of the dlist
 */
#define dlist_is_last(entry, head) \
    ((entry)->next == head)

/**
 * ��ȡ����ĵ�һ���ڵ�
 * @head:    the dlist head to take the element from.
 * @type:    the type of the struct this is embedded in.
 * @member:  the name of the dlist_struct within the struct.
 */
#define dlist_first_entry(head, type, member) \
    (dlist_empty(head) ? NULL : dlist_entry((head)->next, type, member))

/**
 * ��ȡ��������һ���ڵ�
 * @head:    the dlist head to take the element from.
 * @type:    the type of the struct this is embedded in.
 * @member:  the name of the dlist_struct within the struct.
 */
#define dlist_last_entry(head, type, member) \
    (dlist_empty(head) ? NULL : dlist_entry((head)->prev, type, member))

/**
 * �ж������Ƿ�ֻ��һ��entry
 * @head: the dlist to test.
 */
#define dlist_is_singular(head) \
    (!dlist_empty(head) && ((head)->next == (head)->prev))

/**
 * ��ԭ��head�����еĵ�һ��entry�����entry֮���entry�ƶ���new_head����
 * @head:       ԭ����
 * @entry:      ��Ҫ�����������һ��entry��Ӧ��head�����е�һ��entry
 * @new_head:   ���ձ�������entry������Ӧ����һ�������������������ݶ�ʧ����
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
 * �ѱ�ֽ����������ԭ��head�����еĵ�һ��entry�����entry֮���entry�ƶ���new_head����
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
 * ������������һ������嵽��һ�������head_prev��head_next֮��
 * @new_head:   ��Ҫ���������
 * @head_prev:  �����������λ��ǰһ��entry
 * @head_next:  �����������λ�ú�һ��entry
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
 * �ϲ���������һ������嵽��һ�������ͷ��
 * @new_head:   ��Ҫ���������
 * @head:       ��������������γ��µĸ���������
 */
#define dlist_splice(new_head, head) \
do { \
    if (!dlist_empty(new_head)) { \
        __dlist_splice((new_head), (head), head_next); \
    } \
} while (0)

/**
 * ������������һ������嵽��һ�������β��
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
 * ͷ�巨�����������������³�ʼ����յ�����
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
 * β�巨�����������������³�ʼ����յ�����
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
 * �������������ڱ������޸�����
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @head:       the head for your dlist.
 *
 * This variant differs from dlist_for_each() in that it's the
 * simplest possible dlist iteration code, no prefetching is done.
 * Use this for code that knows the dlist to be very short (empty
 * or 1 entry) most of the time.
 *
 * ���ĵ�����ǰ���__dlist_for_each()��ȫһ������Ϊ�����ӿ�
 */
#define __dlist_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/**
 * ��������������ɱ������޸�����
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @head:       the head for your dlist.
 */
#define dlist_for_each_prev(pos, head) \
    for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

/**
 * ��ȫ�ط����������֧�ֱ������޸�����
 * @pos:        the &struct dlist_head to use as a loop cursor.
 * @pos_tmp:    another &struct dlist_head to use as temporary storage
 * @head:       the head for your dlist.
 */
#define dlist_for_each_prev_safe(pos, pos_tmp, head) \
    for ((pos) = (head)->prev, (pos_tmp) = (pos)->prev; \
         (pos) != (head); \
         (pos) = (pos_tmp), (pos_tmp) = (pos)->prev)

/**
 * ѭ������������ڵ㣬�����ڱ������޸�����
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
 * ׼��һ���ڵ㣬����Ϊdlist_for_each_entry_continue�Ⱥ��������pos
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
 * ��pos��Ϊͷ��������������ڵ㣬����pos����һ��λ�ÿ�ʼ����
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
 * ��pos��Ϊͷ�����������������ڵ�
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
 * ��posλ������������ڵ�
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
 * ��pos��Ϊͷ����԰�ȫ�ķ�ʽ������������ڵ㣬����pos����һ��λ�ÿ�ʼ����
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
 * ��posλ�����԰�ȫ�ķ�ʽ���������ڵ�
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
 * �԰�ȫ�ķ�ʽ��������ڵ�
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

