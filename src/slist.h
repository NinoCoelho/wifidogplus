/**
 * ʵ��ͷβ�ɿص���ѭ������
 * ��slist_del_head��slist_add_tail���������ʺ�ʵ�ֶ���
 * ��ֲ��linux֮list.h�����и���ϸ˵����linux֮list.h������������������
 * ���ĵ���ͷentry�������ʾ����˼һ����������ͷentry��ʾ����
 * ���������������˵����Ϊָ��
 * __XXXΪ�ڲ��ӿڣ����ÿ�����Σ�գ�Ϊ���Ƽ�ʹ�õĽӿ�
 * XXX__Ϊ���ܽϲ�Ľӿڣ�Ӧ����ʹ�������ӿ����
 *
 * cjpthree@126.com 2014-4-10 Create
 *
 * ʹ��ʾ����
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
 * ͷentry�ṹ
 * �ĵ���slist_head_t��slist_node_t��ǿ������ת��������next��pptail��˳����Ԫ�ص�˳���ܸı䣬
 * ֧����ֵǿ������ת���ı������ϣ�����ͷentry����ͨentry������Ϊslist_head_t��
 * ��֧����ֵǿ������ת���ı������ϣ��û������ͷentry����Ϊslist_head_t����ͨentry����Ϊslist_node_t��
 */
typedef struct slist_head {
    struct slist_node *next;    /* ����ָ���һ��entry */
    struct slist_node **pptail; /* ����ָ�����һ��entry��next�� */
} slist_head_t;

/**
 * entry�ṹ
 */
typedef struct slist_node {
    struct slist_node *next; /* ָ������entry */
} slist_node_t;

/**
 * ��ʼ������
 */
#define SLIST_HEAD_INIT(name) \
    {(slist_node_t *)&(name), &((name).next)}

/**
 * ���岢��ʼ������
 * @name: ����ı�ʶ��
 */
#define SLIST_HEAD(name) \
    slist_head_t (name) = SLIST_HEAD_INIT(name)

/**
 * ��ʼ������
 * @head: ��Ҫ��ʼ��������
 */
#define INIT_SLIST_HEAD(head) \
do { \
    (head)->next = (slist_node_t *)(head); \
    (head)->pptail = &((head)->next); \
} while (0)

/**
 * ��ʼ��entry
 * @node: ��Ҫ��ʼ����entry
 */
#define INIT_SLIST_NODE(s_node) \
    ((s_node)->next = (slist_node_t *)(s_node))

/**
 * �ж��Ƿ�Ϊ������������ֻ��ͷ���
 * @head: the list to test.
 */
#define slist_empty(head) \
    ((head)->next == (slist_node_t *)(head))

/**
 * �ж������Ƿ�ֻ��һ��entry
 * @head: the list to test.
 */
#define slist_is_singular(head) \
    (!slist_empty(head) && ((head)->pptail == &(head)->next->next))

/**
 * ��ȡ�������һ��entry
 * @head: the list to test.
 */
#define slist_get_last(head) \
    slist_entry((head)->pptail, slist_node_t, next)

/**
 * ��ȡ�����һ��entry
 * @head: the list to test.
 */
#define slist_get_first(head) \
    ((head)->next)

/**
 * ��entry�������һ���µ�entry
 * @new_entry:  Ҫ�����entry
 * @prev_entry: ǰ���Ǹ�entry
 */
#define __slist_add(new_entry, prev_entry) \
do { \
    (new_entry)->next = (prev_entry)->next; \
    (prev_entry)->next = (slist_node_t *)(new_entry); \
} while (0)

/**
 * ͷ�巨������entry
 * @new_entry:  new entry to be added
 * @head:       ͷentry
 */
#define slist_add_head(new_entry, head) \
do { \
    if (slist_empty(head)) { \
        (head)->pptail = &(new_entry)->next; \
    } \
    __slist_add((new_entry), (head)); \
} while (0)

/**
 * β�巨������entry
 * @new_entry:  new entry to be added
 * @head:       ͷentry
 */

#define slist_add_tail(new_entry, head) \
do { \
    __slist_add((new_entry), slist_get_last(head));  \
   (head)->pptail = &(new_entry)->next;  \
} while (0)

/**
* �ں��������entry
* @new_entry:  new entry to be added
* @prev_entry: ����λ��ǰһ��entry
*/
#define slist_add_after(new_entry, prev_entry, head) \
do { \
    if ((slist_node_t *)(prev_entry) == slist_get_last(head)) { \
        (head)->pptail = &(new_entry)->next;  \
    } \
    __slist_add((new_entry), (prev_entry)); \
} while (0)

/**
 * ��ǰ�������entry
 * @new_entry:  ��Ҫ�����entry
 * @next_entry: ��������entryǰ��
 * @head:       ͷentry
 *
 * ��������ͷ��ʼѰ��entry��ǰ�����ҵ������entry
 * ��ʱ�϶࣬���Ƽ�
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
 * ������ɾ��prev_entry�����entry
 * @prev_entry: ��Ҫɾ����entry��ǰ���Ǹ�entry
 */
#define __slist_del(prev_entry) \
    ((prev_entry)->next = (prev_entry)->next->next)

/**
 * ɾ������ĵ�һ��entry
 * @head: ����ͷentry
 *
 * ���ܺã��Ƽ�ʹ��
 */
#define slist_del_head(head) \
do { \
    if (slist_is_singular(head)) { \
        (head)->pptail = &(head)->next; \
    } \
    __slist_del(head); \
} while (0)

/**
 * ɾ����������һ��entry
 * @head: ����ͷentry
 *
 * ���ܵ͵ĺ��������Ƽ�ʹ��
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
 * ɾ�������һ��entry
 * @prev_entry: Ҫɾ����entry��ǰ��һ��entry
 *
 * ���ܺã��Ƽ�ʹ��
 */
#define slist_del_after(prev_entry, head) \
do { \
    if ((slist_node_t *)((prev_entry)->next) == slist_get_last(head)) { \
        (head)->pptail = &(prev_entry)->next; \
    } \
    ((prev_entry)->next != (slist_node_t *)(head)) && __slist_del(prev_entry); \
} while (0)

/**
 * ɾ����ǰentry
 * @entry:  ��Ҫɾ����entry
 * @head:   ͷentry
 *
 * ��������ͷ��ʼѰ��entry��ǰ�����ҵ���ɾ��entry
 * ��ʱ�϶࣬���Ƽ�
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
 * ��ȡ������entry�Ľṹ��ָ��
 * @entry:   �����ڽṹ���е�entry
 * @type:    Ҫ��ȡ�Ľṹ�������
 * @member:  entry�ڽṹ���еı�ʶ��
 */
#define slist_entry(entry, type, member) \
    ((type *)((char *)(entry) - (unsigned long)(&((type *)0)->member)))

/**
 * �������������ڱ������޸�����
 * @pos:    ���������α��entry
 * @head:   the head of your list.
 */
#define slist_for_each(pos, head) \
    for ((pos) = (slist_node_t *)((head)->next); \
        (pos) != (slist_node_t *)(head); \
        (pos) = (slist_node_t *)((pos)->next))

/**
 * ��ȫ�ر�������֧�ֱ�����ɾ���������޸�pos�������޸�prev
 * @pos:        ���������α��entry
 * @pos_prev:   ������posǰ����Ǹ�entry
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
