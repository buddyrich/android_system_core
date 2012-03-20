/*
 * Copyright 2011, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cutils/android_reboot.h>

/* SafeStrap trigger file; chose /cache as it is available from
 * both /system and /systemorig and avoids issues trying to write
 * to the filesystem during the execution of the reboot binary
 * without the proper root permissions */
#define SS_FILE     "/cache/.ss"

static FILE* ssfd;

/* Check to see if /proc/mounts contains any writeable filesystems
 * backed by a block device.
 * Return true if none found, else return false. */
static int remount_ro_done(void)
{
    FILE *f;
    char mount_dev[256];
    char mount_dir[256];
    char mount_type[256];
    char mount_opts[256];
    int mount_freq;
    int mount_passno;
    int match;
    int found_rw_fs = 0;

    f = fopen("/proc/mounts", "r");
    if (! f) {
        /* If we can't read /proc/mounts, just give up */
        return 1;
    }

    do {
        match = fscanf(f, "%255s %255s %255s %255s %d %d\n",
                       mount_dev, mount_dir, mount_type,
                       mount_opts, &mount_freq, &mount_passno);
        mount_dev[255] = 0;
        mount_dir[255] = 0;
        mount_type[255] = 0;
        mount_opts[255] = 0;
        if ((match == 6) && !strncmp(mount_dev, "/dev/block", 10) && strstr(mount_opts, "rw")) {
            found_rw_fs = 1;
            break;
        }
    } while (match != EOF);

    fclose(f);

    return !found_rw_fs;
}

/* Remounting filesystems read-only is difficult when there are files
 * opened for writing or pending deletes on the filesystem.  There is
 * no way to force the remount with the mount(2) syscall.  The magic sysrq
 * 'u' command does an emergency remount read-only on all writable filesystems
 * that have a block device (i.e. not tmpfs filesystems) by calling
 * emergency_remount(), which knows how to force the remount to read-only.
 * Unfortunately, that is asynchronous, and just schedules the work and
 * returns.  The best way to determine if it is done is to read /proc/mounts
 * repeatedly until there are no more writable filesystems mounted on
 * block devices.
 */
static void remount_ro(void)
{
    int fd, cnt = 0;

    /* Trigger the remount of the filesystems as read-only,
     * which also marks them clean.
     */
    fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd < 0) {
        return;
    }
    write(fd, "u", 1);
    close(fd);


    /* Now poll /proc/mounts till it's done */
    while (!remount_ro_done() && (cnt < 50)) {
        usleep(100000);
        cnt++;
    }

    return;
}

int android_reboot(int cmd, int flags, char *arg)
{
    int ret = 0;
    int reason = -1;

/* Want to make sure we don't force all the partitions readonly 
 * before writing to our trigger file; hopefully, this won't
 * cause any issues in terms of rebooting without syncing.
 * Note that this only kicks in if ANDROID_RB_RESTART2 is sent
 * as the internal reason code (cmd) for the restart; this only
 * applies when a reboot into recovery/bootloader is requested.*/ 
#ifdef RECOVERY_PRE_COMMAND
    if (cmd == (int) ANDROID_RB_RESTART2) {
        if (arg && strlen(arg) > 0) { 
            flags = ANDROID_RB_FLAG_NO_SYNC | ANDROID_RB_FLAG_NO_REMOUNT_RO;
            char r_cmd[PATH_MAX];
	    sprintf(r_cmd, RECOVERY_PRE_COMMAND);
	    system(r_cmd);
        }
    } 
#endif

    if (!(flags & ANDROID_RB_FLAG_NO_SYNC))
	sync();

    if (!(flags & ANDROID_RB_FLAG_NO_REMOUNT_RO))
        remount_ro(); 
    
    /* Checking the internal reboot reason code and deciding 
     * what to do. */
    switch (cmd) {
        case ANDROID_RB_RESTART:
            reason = RB_AUTOBOOT;
            break;

        case ANDROID_RB_POWEROFF:
            ret = reboot(RB_POWER_OFF);
	    //ret = __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF, NULL);
            return ret;

        case ANDROID_RB_RESTART2:
            // REBOOT_MAGIC
            break;

        default:
            return -1;
    }

/* Want to clear the reason to RB_AUTOBOOT so that the kernel
 * performs a regular reboot instead of trying to initiate a
 * reboot into the stock recovery/bootloader */
#ifdef RECOVERY_PRE_COMMAND_CLEAR_REASON
    reason = RB_AUTOBOOT;
#endif
    
    int ro_poll_cnt = 0;

    if (reason != -1) { 
	
	/* Doubtful that there'd be any reason to pass in an argument
	 * of more than 64 characters, but if that happens there'll
 	 * just be a segmentation fault */
	char *r_arg = (char *)calloc(strlen("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"), sizeof(char));     
	
	/* If there's no argument then perform a normal reboot */
	if ((arg) && strlen(arg) > 0) {
		strcpy(r_arg,arg);
	} else {
		ret = reboot(reason);
	}
        
	/* If the reboot reason passed in from the OS was the string
         * "recovery", then skip the system call (__reboot) and
	 * perform a normal reboot after marking the recovery trigger
	 * file at /cache/.ss */
	if( !(strcmp(r_arg,"recovery")) ) {
		
		ssfd = fopen(SS_FILE, "w");
                fwrite("1\n", sizeof(char), 2, ssfd);
                fclose(ssfd);
		sync();
		
        	ret = reboot(reason);

	/* If the reason sent in was "bp-tools", then reboot directly
	 * into the stock recovery.  (ie: /system/bin/reboot bp-tools)
	 * note the system call to __reboot, if we sent "bp-tools" as
	 * the reason, the kernel simply performs an ordinary reboot */
	} else if( !(strcmp(r_arg,"bp-tools")) ) {
		
		ssfd = fopen(SS_FILE, "w");
                fwrite("0\n", sizeof(char), 2, ssfd);
                fclose(ssfd);
		sync();
		
		char reboot_arg[strlen("recovery")];
		sprintf(reboot_arg, "recovery" );	
		ret = __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, reboot_arg);
	
	/* Self-explanatory */
	} else if( !(strcmp(r_arg,"bootloader")) ) {
		
		ssfd = fopen(SS_FILE, "w");
                fwrite("0\n", sizeof(char), 2, ssfd);
                fclose(ssfd);
		sync();
		
		char reboot_arg[strlen("bootloader")];
		sprintf(reboot_arg, "bootloader" );	
		ret = __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, reboot_arg);
	
	}
     } 
 
     return ret;
}
