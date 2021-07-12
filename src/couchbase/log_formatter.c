/**
 *     Copyright 2016-2019 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdarg.h>
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER < 1900

#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

__inline int c99_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    int count = -1;

    if (size != 0) {
        count = _vsnprintf_s(buf, size, _TRUNCATE, fmt, ap);
    }
    if (count == -1) {
        count = _vscprintf(fmt, ap);
    }

    return count;
}

__inline int c99_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    int count;
    va_list ap;

    va_start(ap, fmt);
    count = c99_vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    return count;
}

#endif

#define PCBC_LOG_MSG_SIZE 1024

void pcbc_log_formatter(char *buf, int buf_size, const char *severity, const char *subsystem, int srcline,
                        int instance_id, void *instance_ptr, int is_lcb, const char *fmt, va_list ap)
{
    char msg[PCBC_LOG_MSG_SIZE] = {0};
    int i;

    vsnprintf(msg, PCBC_LOG_MSG_SIZE, fmt, ap);
    msg[PCBC_LOG_MSG_SIZE - 1] = '\0';
    for (i = 0; i < PCBC_LOG_MSG_SIZE; i++) {
        if (msg[i] == '\n' || msg[i] == '\r') {
            msg[i] = ' ';
        }
    }
    if (is_lcb) {
        snprintf(buf, buf_size, "[cb,%s] (%s L:%d I:%u) %s", severity, subsystem, srcline, (unsigned int)instance_id,
                 msg);
    } else if (instance_ptr) {
        snprintf(buf, buf_size, "[cb,%s] (%s L:%d) %s. I=%p", severity, subsystem, srcline, msg, instance_ptr);
    } else {
        snprintf(buf, buf_size, "[cb,%s] (%s L:%d) %s", severity, subsystem, srcline, msg);
    }
}
