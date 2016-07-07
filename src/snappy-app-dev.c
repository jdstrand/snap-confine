/*
 * Copyright (C) 2016 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* #include "config.h"
#include "utils.h"
#include "snap.h"
#include "cleanup-funcs.h"
*/

/* temporary */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* temporary */

#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* temporary */
#include <stdarg.h>
#include <errno.h>
void die(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	vfprintf(stderr, msg, va);
	va_end(va);

	if (errno != 0) {
		perror(". errmsg");
	} else {
		fprintf(stderr, "\n");
	}
	exit(1);
}

#include <stdbool.h>
#include <stddef.h>
bool verify_security_tag(const char *security_tag)
{
	// The executable name is of form:
	// snap.<name>.(<appname>|hook.<hookname>)
	// - <name> must start with lowercase letter, then may contain
	//   lowercase alphanumerics and '-'
	// - <appname> may contain alphanumerics and '-'
	// - <hookname must start with a lowercase letter, then may
	//   contain lowercase letters and '-'
	const char *whitelist_re =
	    "^snap\\.[a-z](-?[a-z0-9])*\\.([a-zA-Z0-9](-?[a-zA-Z0-9])*|hook\\.[a-z](-?[a-z])*)$";
	regex_t re;
	if (regcomp(&re, whitelist_re, REG_EXTENDED | REG_NOSUB) != 0)
		die("can not compile regex %s", whitelist_re);

	int status = regexec(&re, security_tag, 0, NULL, 0);
	regfree(&re);

	return (status == 0);
}

int must_snprintf(char *str, size_t size, const char *format, ...)
{
	int n = -1;

	va_list va;
	va_start(va, format);
	n = vsnprintf(str, size, format, va);
	va_end(va);

	if (n < 0 || n >= size)
		die("failed to snprintf %s", str);

	return n;
}

void sc_cleanup_string(char **ptr)
{
	free(*ptr);
}

void write_string_to_file(const char *filepath, const char *buf)
{
	FILE *f = fopen(filepath, "w");
	if (f == NULL)
		die("fopen %s failed", filepath);
	if (fwrite(buf, strlen(buf), 1, f) != 1)
		die("fwrite failed");
	if (fflush(f) != 0)
		die("fflush failed");
	if (fclose(f) != 0)
		die("fclose failed");
}

/* end temporary */

bool is_block(const char *devpath)
{
	const char *block_re = "^/.+/block/.+$";
	regex_t re;
	if (regcomp(&re, block_re, REG_EXTENDED | REG_NOSUB) != 0)
		die("can not compile regex %s", block_re);

	int status = regexec(&re, devpath, 0, NULL, 0);
	regfree(&re);

	return (status == 0);
}

int main(int argc, char *argv[])
{
	if (argc < 5)
		die("Usage: %s <action> <sectag> <devpath> <major:minor>",
		    argv[0]);

	const char *action = argv[1];
	const char *sectag = argv[2];
	const char *devpath = argv[3];
	const char *majmin = argv[4];

	// verify action
	if (strcmp(action, "add") != 0 && strcmp(action, "change") != 0
	    && strcmp(action, "remove") != 0)
		die("action must be one of 'add', 'change' or 'remove'");

	// verify sectag
	if (!verify_security_tag(sectag))
		die("invalid security tag");

	// verify file exists under /sys
	char *sys_path = "/sys";
	char sys_devpath[PATH_MAX];
	must_snprintf(sys_devpath, sizeof(sys_devpath), "%s%s", sys_path,
		      devpath);
	if (access(sys_devpath, F_OK) != 0)
		die("devpath does not exist under /sys");

	// verify major:minor
	const char *majmin_re = "^[0-9]+:[0-9]+$";
	regex_t re;
	if (regcomp(&re, majmin_re, REG_EXTENDED | REG_NOSUB) != 0)
		die("can not compile regex %s", majmin_re);

	if (regexec(&re, majmin, 0, NULL, 0) != 0) {
		regfree(&re);
		die("major:minor is not of form 'XX:YY'");
	}
	regfree(&re);

	// Build up the cgroup name in /sys/fs
	char *cgroup_top = "/sys/fs/cgroup/devices/";
	char cgroup_name[PATH_MAX];
	must_snprintf(cgroup_name, sizeof(cgroup_name), "%s%s", cgroup_top,
		      sectag);
	for (int i = strlen(cgroup_top); i < strlen(cgroup_name); i++)
		if (cgroup_name[i] == '.')
			cgroup_name[i] = '_';

	char type = 'c';
	if (is_block(devpath))
		type = 'b';

	char *perms = "rwm";
	// '<type> <majmin> <perms>\0'
	char acl[strlen(majmin) + strlen(perms) + 4];
	must_snprintf(acl, sizeof(acl), "%c %s %s", type, majmin, perms);

	char cgroup_path[PATH_MAX];
	if (strcmp(action, "add") == 0 || strcmp(action, "change") == 0)
		must_snprintf(cgroup_path, sizeof(cgroup_path), "%s%s",
			      cgroup_name, "/devices.allow");
	else
		must_snprintf(cgroup_path, sizeof(cgroup_path), "%s%s",
			      cgroup_name, "/devices.deny");

	if (secure_getenv("SNAPPY_LAUNCHER_INSIDE_TESTS") == NULL)
		write_string_to_file(cgroup_path, acl);
	else
		printf("%s %s\n", cgroup_path, acl);

	return 0;
}
