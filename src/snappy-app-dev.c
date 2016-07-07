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

#include "config.h"
#include "utils.h"
#include "snap.h"
#include "cleanup-funcs.h"

#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
