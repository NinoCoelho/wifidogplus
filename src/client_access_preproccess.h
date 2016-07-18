/**
 * Copyright(C) 2015. 1dcq. All rights reserved.
 *
 * client_access_preproccess.h
 * Original Author : cjpthree@126.com, 2015-7-6.
 *
 * Description
 */

#ifndef _CLIENT_ACCESS_PREPROCCESS_H_
#define _CLIENT_ACCESS_PREPROCCESS_H_

extern sem_t sem_client_access_preproccess;

int thread_client_access_preproccess(char *arg);

#endif      /* _CLIENT_ACCESS_PREPROCCESS_H_ */

