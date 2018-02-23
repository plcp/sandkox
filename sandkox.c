#define _GNU_SOURCE

#include <linux/securebits.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <grp.h>
#include <pwd.h>

#define _arg1 0, 0, 0, 0
#define _arg2 0, 0, 0

#define SUID_DUMP_DISABLE 0
#ifndef SANDKOX_FID_LIMIT
    #define SANDKOX_FID_LIMIT 60000
#endif

extern int errno;

#ifndef SANDKOX_DETACH_CHILD__
    static size_t _sndkx_argc = 0;
    static char** _sndkx_argv = NULL;

    static void cname(char name[])
    {
        if(!_sndkx_argc || !_sndkx_argv)
            return;

        prctl(PR_SET_NAME, name);
        strncpy(_sndkx_argv[0], name, strlen(_sndkx_argv[0]));
    }
#endif

static void die(const char error[])
{
    fprintf(stderr, "Fatal: %s", error);
    if(errno)
        perror(" :");
    exit(-1);
}

static gid_t _sndkx_fgid;
static uid_t _sndkx_fuid;
static int filter_fids(const struct dirent* dir)
{
    char filename[12 + 256 + 1];
    snprintf(filename, 12 + 256 + 1, "/proc/%s", dir->d_name);

    struct stat entry;
    if(stat(filename, &entry))
        return 0;

    if(entry.st_gid == _sndkx_fgid)
        _sndkx_fgid = 0;

    if(entry.st_uid == _sndkx_fuid)
        _sndkx_fuid = 0;

    return 0;
}

static gid_t get_fgid()
{
    struct dirent** namelist;

    int race = 1;
    gid_t gid = SANDKOX_FID_LIMIT;
    while(race)
    {
        gid -= 1;

        struct group* group = getgrgid(gid);
        if(group)
            continue;

        _sndkx_fgid = gid;
        if(scandir("/proc", &namelist, filter_fids, NULL))
            die("Error while scanning /proc entries");

        if(!_sndkx_fgid)
            continue;

        race = 0;
    }

    return gid;
}

static uid_t get_fuid()
{
    struct dirent** namelist;

    int race = 1;
    uid_t uid = SANDKOX_FID_LIMIT;
    while(race)
    {
        uid -= 1;

        struct passwd* passwd = getpwuid(uid);
        if(passwd)
            continue;

        _sndkx_fuid = uid;
        if(scandir("/proc", &namelist, filter_fids, NULL))
            die("Error while scanning /proc entries");

        if(!_sndkx_fuid)
            continue;

        race = 0;
    }

    return uid;
}

static gid_t sudo_gid()
{
    const char *sudo_gid = secure_getenv("SUDO_GID");
    if(sudo_gid == NULL)
        return -1;

    errno = 0;
    gid_t gid = (gid_t) strtoll(sudo_gid, NULL, 10);
    if(errno != 0)
        die("Invalid SUDO_GID env variable");

    return gid;
}

static uid_t sudo_uid()
{
    const char *sudo_uid = secure_getenv("SUDO_UID");
    if(sudo_uid == NULL)
        return -1;

    errno = 0;
    uid_t uid = (uid_t) strtoll(sudo_uid, NULL, 10);
    if(errno != 0)
        die("Invalid SUDO_UID env variable");

    return uid;
}

void drop_gid()
{
    gid_t rgid, egid, sgid;
    if((rgid = sudo_gid()) != (gid_t) -1)
        setgid(rgid);
    else if(getresgid(&rgid, &egid, &sgid))
        die("Unable to get real, effective, saved gid");

    rgid = (rgid == 0) ? get_fgid() : rgid;
    if(setresgid(rgid, rgid, rgid))
        die("Unable to drop root gid");

    if(setgroups(0, NULL))
        die("Unable to drop supplementary groups");
}

void drop_uid()
{
    uid_t ruid, euid, suid;
    if((ruid = sudo_uid()) != (uid_t) -1)
        setuid(ruid);
    else if(getresuid(&ruid, &euid, &suid))
        die("Unable to get real, effective, saved uid");

    ruid = (ruid == 0) ? get_fuid() : ruid;
    if(setresuid(ruid, ruid, ruid))
        die("Unable to drop root uid");
}

static void drop_chk()
{
    if(setresuid(0, 0, 0) == 0 || setresgid(0, 0, 0) == 0)
        die("Unable to effectively drop root privileges, exiting now.");

    if(!setuid(0) || !seteuid(0) || !setgid(0) || !setegid(0))
        die("Unable to effectively drop root privileges, exiting now.");
}

void drop_ptrace()
{
    if(prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE, _arg2))
        die("Unable to disable suid dump");

    if(prctl(PR_GET_DUMPABLE, _arg1))
        die("Unable to set dumpable flag");
}

void drop_root()
{
    drop_ptrace();
    drop_gid();
    drop_uid();
    drop_chk();
}

static void perm_caps(int n)
{
    cap_value_t capability[3] = {
        CAP_SETPCAP,
        CAP_SETUID,
        CAP_SETGID
    };
    cap_t capabilities = cap_get_proc();

    if(cap_clear(capabilities))
        die("Unable to clean capabilities");

    if(n > 0)
    {
        if(cap_set_flag(capabilities, CAP_EFFECTIVE, n, capability, CAP_SET))
            die("Unable to set capability set to effective");

        if(cap_set_flag(capabilities, CAP_PERMITTED, n, capability, CAP_SET))
            die("Unable to set capability set to permitted");

        if(cap_set_flag(capabilities, CAP_INHERITABLE, n, capability, CAP_SET))
            die("Unable to set capability set to permitted");
    }

    if(cap_set_proc(capabilities))
        die("Unable to set capabilities before dropping privileges");

    if(cap_free(capabilities))
        die("Unable to free capability descriptor");
}

static void save_caps()
{
    int cap = 0;
    for(; cap < 64; ++cap)
    {
        if(0x0
            || cap == CAP_SETPCAP
            || cap == CAP_SETUID
            || cap == CAP_SETGID)
            continue;

        if(prctl(PR_CAPBSET_DROP, cap, _arg2) && errno != EINVAL)
            die("Unable to drop all capabilities");
    }

    perm_caps(3);
    if(prctl(PR_SET_KEEPCAPS, 1, _arg2))
        die("Unable to keep capabilities while dropping privileges");
}

static void keep_caps()
{
    perm_caps(3);
    if(prctl(PR_SET_KEEPCAPS, 0, _arg2))
        die("Unable to disable capability keeping");

    if(prctl(PR_CAPBSET_DROP, CAP_SETUID, _arg2))
        die("Unable to drop setuid capability");

    if(prctl(PR_CAPBSET_DROP, CAP_SETGID, _arg2))
        die("Unable to drop setgid capability");

    perm_caps(1);
}

void drop_priv()
{
    // drops root privileges...
    save_caps();
    drop_root();
    keep_caps();
    // ...but keeps CAP_SET_PCAP for later
}

void lock_news()
{
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, _arg2))
        die("Unable to lock privileges");

    if(prctl(PR_GET_NO_NEW_PRIVS, _arg1) != 1)
        die("Unable to set no_new_privs");
}

void lock_bits()
{
    if(prctl(PR_SET_KEEPCAPS, 0, _arg2))
        die("Unable to disable capability keeping");

    if(prctl(PR_SET_SECUREBITS, 0x0
        | SECBIT_KEEP_CAPS_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED
        | SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED, _arg1))
        die("Unable to lock secure bits");

    if(prctl(PR_GET_SECUREBITS) != 0x2F)
        die("Unable to set secure bits");
}

void lock_caps()
{
    int cap = 0;
    for(; cap < 64; ++cap)
        if(prctl(PR_CAPBSET_DROP, cap, _arg2) && errno != EINVAL)
            die("Unable to drop all capabilities");

    perm_caps(0);
}

void lock_priv()
{
    // locks further privileges...
    lock_news();
    lock_bits();
    lock_caps();
    // ...and drop any extra capabilities
}

static int hand(int socket)
{
    char msg;
    ssize_t bytes;
    do
    {
        errno = 0;
        bytes = write(socket, &msg, 1);
    } while(bytes == -1 && errno == EINTR);

    if(bytes == 1 && !errno)
        return 0;
    return -1;
}

static int shake(int socket)
{
    char msg = 1;
    ssize_t bytes;
    do
    {
        errno = 0;
        bytes = read(socket, &msg, 1);
    } while (bytes == -1 && errno == EINTR);

    if(bytes == 1 && !errno)
        return 0;
    return -1;
}

int jail_strap(char safedir[])
{
    int socket[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, socket))
        die("Unable to create socket pair");

    pid_t pid = syscall(__NR_clone, CLONE_FS | SIGCHLD, _arg1);

    if(pid == -1)
        die("Unable to properly clone parent process");

    if(pid == 0)
    {
        if(close(socket[1]))
            die("Unable to close socket");

        // limiting descriptors
        const struct rlimit nofile = {0, 0};
        if(setrlimit(RLIMIT_NOFILE, &nofile))
            die("Unable to limit maximum valid descriptor");

        // wait for parent
        drop_ptrace();
        if(shake(socket[0]))
            die("Unable to get notified by jailed parent");

        if(chdir(safedir))
            die("Unable to change directory to safe directory");

        // chroot
        if(chroot(safedir))
            die("Unable to chroot to safe directory");

        // stay privileged to prevents unprivileged processes from accessing
        // our proc(5) pseudo-files (see ptrace(2) & search PTRACE_MODE_*)
        lock_bits();
        lock_caps();

        // effectively change directory
        if(chdir("/"))
            die("Unable to change directory to / after chroot");

        if(hand(socket[0]))
            die("Unable to notify jailed parent");

        exit(0);
    }

    if(close(socket[0]))
        die("Unable to close socket");

    return socket[1];
}

void jail_final(int socket)
{
    drop_chk();
    if(hand(socket))
        die("Unable to trigger jail setup");

    if(shake(socket))
        die("Unable to confirm jail setup");

    if(close(socket))
        die("Unable to close trigger socket");

    // wait for the child to finish
    int wstatus;
    waitpid(-1, &wstatus, 0);
}

void sandkox()
{
    pid_t pid = syscall(__NR_clone, CLONE_NEWPID | SIGCHLD, _arg1);
    if(pid < 0)
        die("Unable to checkout fresh pid namespace");

    if(pid > 0)
    {
        #ifndef SANDKOX_DETACH_CHILD__
            cname("sandkox");

            int wstatus;
            waitpid(-1, &wstatus, 0);
        #endif

        exit(0);
    }

    int s = jail_strap("/proc/self/fdinfo/");

    drop_priv();
    lock_priv();

    jail_final(s);
}

#ifdef SANDKOX_NOSTARTFILES__
    void _init(int argc, char** argv, char** envp)
    {
        void (*_ginit)(int, char**, char**);
        *(void**) (&_ginit) = dlsym(RTLD_NEXT, "_init");

        if(!_ginit)
            die("Unable to retrieve libc _init");

        #ifndef SANDKOX_DETACH_CHILD__
            _sndkx_argc = argc;
            _sndkx_argv = argv;
        #endif

        sandkox();
        _ginit(argc, argv, envp);
    }
#endif

