/* Real confined filesystem operations with an unavailable openat2 boundary. */
#include "fs/path/path_internal.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <dirent.h>

typedef struct { ngx_cycle_t cycle; int unavailable; } fixture;
/* WHAT: Model a kernel syscall refusal. WHY: Exercise fallback errors without changing filesystem behavior. HOW: Return errno at the PAL boundary. */
int __wrap_brix_plat_openat2(int rootfd, const char *rel, int flags,
    mode_t permissions, uint64_t resolve)
{
    (void)rootfd;(void)rel;(void)flags;(void)permissions;(void)resolve;
    errno=((fixture *)ngx_cycle)->unavailable;return -1;
}
/* WHAT: Count owned descriptors. WHY: Detect leaks on refused parent walks. HOW: Count this process's descriptor directory. */
static unsigned descriptors(void)
{
    DIR *dir=opendir("/proc/self/fd");assert(dir);unsigned count=0;
    while(readdir(dir)) { count++; }
    assert(closedir(dir)==0);return count;
}
/* WHAT: Close an owned result. WHY: Verify close-on-exec and avoid fixture leaks. HOW: Check then release the descriptor. */
static int consume_fd(int fd, int cloexec)
{
    if(fd<0) { return -1; }
    if(cloexec) { assert(fcntl(fd,F_GETFD)&FD_CLOEXEC); }
    assert(close(fd)==0);return 0;
}
/* WHAT: Execute a confined metadata operation. WHY: Check both-path and final-component confinement. HOW: Dispatch to the shared helper. */
static int operation(ngx_log_t *log,const char *op,const char *root,const char *path,const char *dest)
{
    if(!strcmp(op,"open")) { return consume_fd(brix_open_confined_canon(log,root,path,O_RDONLY,0),1); }
    if(!strcmp(op,"mkdir")) { return brix_mkdir_confined_canon(log,root,path,0751); }
    if(!strcmp(op,"unlink")) { return brix_unlink_confined_canon(log,root,path,0); }
    if(!strcmp(op,"rmdir")) { return brix_unlink_confined_canon(log,root,path,1); }
    if(!strcmp(op,"rename")) { return brix_rename_confined_canon(log,root,path,dest); }
    if(!strcmp(op,"rename-excl")) { return brix_rename_confined_canon_excl(log,root,path,dest); }
    if(!strcmp(op,"link")) { return brix_link_confined_canon(log,root,path,dest); }
    if(!strcmp(op,"chmod")) { return brix_chmod_confined_canon(log,root,path,06751); }
    if(!strcmp(op,"symlink")) { return brix_symlink_confined_canon(log,root,"../target",path); }
    struct timespec times[2]={{1234567890,0},{1234567891,0}};
    return brix_setattr_confined_canon(log,root,path,1,times,0,(uid_t)-1,(gid_t)-1);
}
/* WHAT: Run one isolated filesystem contract. WHY: Observe mutations and errors. HOW: Use temporary paths and compare descriptor ownership. */
int main(int argc,char **argv)
{
    assert(argc==6);fixture f={0};ngx_cycle=&f.cycle;f.unavailable=atoi(argv[5]);
    ngx_open_file_t file={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_ERR,.file=&file};
    f.cycle.log=&log;ngx_time_init();unsigned before=descriptors();int rc;
    errno=0;
    if(!strcmp(argv[1],"parent")) {
        int rootfd=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(rootfd>=0);
        int fd=brix_open_confined_parent_fallback(rootfd,argv[3]);int error=errno;
        rc=consume_fd(fd,0);assert(close(rootfd)==0);errno=error;
    } else if(!strcmp(argv[1],"bad-rootfd")) {
        rc=consume_fd(brix_open_confined_parent_fallback(-1,argv[3]),0);
    } else { rc=operation(&log,argv[1],argv[2],argv[3],argv[4]); }
    int error=errno;assert(descriptors()==before);
    printf("rc=%d error=%d\n",rc,rc<0?error:0);return 0;
}
