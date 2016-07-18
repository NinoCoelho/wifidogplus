/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file debug.h
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include "conf.h"

/** @brief Used to output messages.
 *The messages will include the finlname and line number, and will be sent to syslog if so configured in the config file
 */

#define debug(level, format, ...) \
do { \
    if (config_get_config()->log_location) { \
        _debug(level, "[%s:%d] "format, __FILE__, __LINE__, ## __VA_ARGS__); \
    } else { \
        _debug(level, format, ## __VA_ARGS__); \
    } \
} while (0);

/** @internal */
void _debug(int level, const char *format, ...);

#endif /* _DEBUG_H_ */
