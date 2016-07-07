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
	const char *block_re =
	    "^/.+/block/.+$";
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
	if (strcmp(action, "add") != 0 && strcmp(action, "change") != 0 && strcmp(action, "remove") != 0)
		die("action must be one of 'add', 'change' or 'remove'");

	// verify sectag
	if (!verify_security_tag(sectag))
		die("invalid security tag");

	// verify file exists under /sys
	char *sys_path = "/sys";
	char sys_devpath[strlen(sys_path) + strlen(devpath) + 1];
	must_snprintf(sys_devpath, sizeof(sys_devpath), "%s%s", sys_path, devpath);
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
	char cgroup_path[strlen(cgroup_top) + strlen(sectag) + 1];
	must_snprintf(cgroup_path, sizeof(cgroup_path), "%s%s", cgroup_top, sectag);
	for (int i=strlen(cgroup_top); i < strlen(cgroup_path); i++)
		if (cgroup_path[i] == '.')
			cgroup_path[i] = '_';

	char type = 'c';
	if (is_block(devpath))
		type = 'b';

	char *perms = "rwm";
	char acl[strlen(majmin) + strlen(perms) + 4]; // '<type> <majmin> <perms>\0'
	must_snprintf(acl, sizeof(acl), "%c %s %s", type, majmin, perms);

	printf("ACTION=%s\nSECTAG=%s\nDEVPATH=%s\nMAJMIN=%s\n", action, sectag, devpath, majmin);
	printf("cgroup_path=%s\nsys_devpath=%s\ntype=%c\nacl=%s\n", cgroup_path, sys_devpath, type, acl);

	if (strcmp(action, "add") == 0 || strcmp(action, "change") == 0) {
		char *bn = "/devices.allow";
		char fn[strlen(cgroup_path) + strlen(bn) + 1];
		must_snprintf(fn, sizeof(fn), "%s%s", cgroup_path, bn);
		printf("write_string_to_file(%s, %s)\n", fn, acl);
	} else {
		char *bn = "/devices.deny";
		char fn[strlen(cgroup_path) + strlen(bn) + 1];
		must_snprintf(fn, sizeof(fn), "%s%s", cgroup_path, bn);
		printf("write_string_to_file(%s, %s)\n", fn, acl);
	}


	return 0;
}
