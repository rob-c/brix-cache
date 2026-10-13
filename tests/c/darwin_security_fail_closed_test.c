/* Native contract checks for the Darwin legacy confinement adapter. */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int brix_security_init(const char *profile);
int brix_security_enable_audit(void);
int brix_security_load_profile(const char *path);
int brix_plat_prctl(int option, unsigned long arg);
int brix_plat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int brix_plat_setresuid(uid_t ruid, uid_t euid, uid_t suid);

int
main(int argc, char **argv)
{
    assert(argc == 2);

    if (strcmp(argv[1], "disabled") == 0) {
        assert(brix_security_init(NULL) == 0);
        assert(brix_security_init("off") == 0);
        return 0;
    }

    errno = 0;
    if (strcmp(argv[1], "requested") == 0) {
        assert(brix_security_init("enforce") == -1);
        assert(errno == ENOTSUP);
        errno = 0;
        assert(brix_security_init("audit") == -1);
        assert(errno == ENOTSUP);
        errno = 0;
        assert(brix_security_init("default") == -1);
        assert(errno == ENOTSUP);
        errno = 0;
        assert(brix_security_enable_audit() == -1);
        assert(errno == ENOTSUP);
        return 0;
    }

    if (strcmp(argv[1], "no-new-privileges") == 0) {
        pid_t child;
        int   status;

        errno = 0;
        assert(brix_plat_prctl(38, 1) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            execl("/usr/bin/true", "true", (char *) NULL);
            _exit(errno == EPERM ? 73 : 74);
        }
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == 73);
        errno = 0;
        {
            uid_t ruid, euid, suid;
            assert(brix_plat_getresuid(&ruid, &euid, &suid) == -1);
            assert(errno == ENOTSUP);
        }
        errno = 0;
        assert(brix_plat_setresuid(1, 1, 1) == -1);
        assert(errno == ENOTSUP);
        return 0;
    }

    assert(strcmp(argv[1], "custom-profile") == 0);
    errno = 0;
    assert(brix_security_load_profile("/tmp/untrusted.sb") == -1);
    assert(errno == ENOTSUP);
    return 0;
}
