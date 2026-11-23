#include <os/log.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

// Keep the values in sync with LogCategory in console_log.rs.
typedef enum {
    ENCFS_LOG_DIAGNOSTICS = 0,
    ENCFS_LOG_IDLE_LOCK = 1,
    ENCFS_LOG_CATEGORY_COUNT,
} encfs_log_category;

static struct {
    const char *name;
    os_log_t log;
} categories[ENCFS_LOG_CATEGORY_COUNT] = {
    [ENCFS_LOG_DIAGNOSTICS] = { .name = "diagnostics" },
    [ENCFS_LOG_IDLE_LOCK] = { .name = "idle_lock" },
};
static pthread_once_t console_log_once = PTHREAD_ONCE_INIT;

static void init_console_log(void) {
    for (size_t i = 0; i < ENCFS_LOG_CATEGORY_COUNT; ++i) {
        categories[i].log = os_log_create("vgough.encfs", categories[i].name);
    }
}

void encfs_console_log(const char *message, encfs_log_category category, bool error) {
    pthread_once(&console_log_once, init_console_log);
    os_log_with_type(categories[category].log,
                     error ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_DEFAULT,
                     "%{public}s", message);
}
