#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <lvm2app.h>

using namespace std;

void on_close_signal(int sig) {
    cout << "caught signal " << sig << endl;
}

void install_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_close_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

struct sparse_file {

    int fd;
    string path;
    int size;

    sparse_file(uint64_t size) {
        this->size = size;

        char *envhome = getenv("HOME");
        string home;
        if (envhome == NULL) {
            home = "/tmp";
        } else {
            home = envhome;
        }

        string dir = home + "/.spinner";
        if (mkdir(dir.c_str(), 0755)) {
            if (errno != EEXIST) {
                throw runtime_error("failed to create " + dir);
            }
        }

        char *cpath = (char*) calloc(dir.size() + 32, 1);
        strcat(cpath, dir.c_str());
        strcat(cpath, "/store-XXXXXX");

        fd = mkstemp(cpath);
        if (fd == -1)
            throw runtime_error("failed to create store (open) " + path);

        path = cpath;
        free(cpath);

        FILE *file = fdopen(fd, "w");
        if (fseek(file, size - 1, SEEK_SET)) {
            throw runtime_error("failed to create store (seek) " + path);
        }
        char null_byte = 0;
        if (fwrite(&null_byte, 1, 1, file) != 1) {
            throw runtime_error("failed to create store (write) " + path);
        }
        if (fflush(file)) {
            throw runtime_error("failed to create store (flush) " + path);
        }
    }

    virtual ~sparse_file() {
        close(fd);
        unlink(path.c_str());
    }
};

struct loopback {

    int fd;
    int id;
    string path;

    loopback(sparse_file &store) {
        bool created;
        for (int i = 0; i < 256; i++) {
            path = "/dev/loop" + to_string(i);
            if (mknod(path.c_str(), S_IFBLK | 0660, makedev(7, i))) {
                if (errno == EEXIST)
                    continue;
                throw runtime_error("failed to create loop device " + to_string(errno));
            }                        

            fd = open(path.c_str(), O_RDWR);
            if (fd == -1) {
                unlink(path.c_str());
                cerr << "failed to open loop " << path << " " << to_string(errno) << endl;
                continue;
            }
            if (ioctl(fd, LOOP_SET_FD, store.fd)) {
                close(fd);
                unlink(path.c_str());
                cerr << "failed to attach loop " << path << " " << to_string(errno) << endl;
                continue;
            }

            id = i;
            created = true;
            break;
        }
        if (!created) {
            throw runtime_error("could not find any good loop devices");
        }        
    }

    virtual ~loopback() {        
        ioctl(fd, LOOP_CLR_FD);
        close(fd);
        unlink(path.c_str());
    }
};

struct lvm_handle {

    lvm_t lvm;

    lvm_handle() {
        lvm = lvm_init(NULL);
        if (lvm == NULL)
            throw runtime_error("failed to init lvm");
    }

    virtual ~lvm_handle() {
        lvm_quit(lvm);
    }
};

struct volume_group {

    lvm_handle &lh;
    loopback &lo;

    volume_group(lvm_handle &lh, loopback &lo) : lh(lh), lo(lo) {
        vg_t vg = lvm_vg_create(lh.lvm, name().c_str());
        if (vg == NULL) {
            throw runtime_error("failed to vg_create");
        }
        if (lvm_vg_extend(vg, lo.path.c_str())) {
            throw runtime_error("failed to vg_extend");
        }
        if (lvm_vg_write(vg)) {
            throw runtime_error("failed to vg_write");
        }
        lvm_vg_close(vg);
    }

    string name() {
        return "spinner" + to_string(lo.id);
    }

    virtual ~volume_group() {
        vg_t vg = lvm_vg_open(lh.lvm, name().c_str(), "w", 0);
        if (vg != NULL) {
            lvm_vg_remove(vg);
            lvm_vg_write(vg);
            lvm_vg_close(vg);
        }
    }
};

struct spinner_volume {

    volume_group &vg_info;
    string name;
    char *uuid;

    spinner_volume(volume_group &vg_info, const string &name, uint64_t size) : vg_info(vg_info) {
        vg_t vg = lvm_vg_open(vg_info.lh.lvm, vg_info.name().c_str(), "w", 0);
        if (vg == NULL)
            throw runtime_error("failed to open volume group " + vg_info.name());        

        lv_t volume = lvm_vg_create_lv_linear(vg, name.c_str(), size);
        if (volume == NULL) {
            lvm_vg_close(vg);
            throw runtime_error("failed to allocate volume " + name);
        }
        uuid = strdup(lvm_lv_get_uuid(volume));
        if (lvm_vg_close(vg))
            throw runtime_error("failed to close volume group " + vg_info.name());

        this->name = name;
    }

    string path() {
        return "/dev/" + vg_info.name() + "/" + name;
    }

    virtual ~spinner_volume() {
        vg_t vg = lvm_vg_open(vg_info.lh.lvm, vg_info.name().c_str(), "w", 0);
        if (vg) {
            lv_t volume = lvm_lv_from_uuid(vg, uuid);
            if (volume) {
                lvm_vg_remove_lv(volume);
            }
            lvm_vg_close(vg);
        }
        free(uuid);
    }
};

void mkfs(const string &dev) {
    pid_t pid = fork();
    if (pid == -1)
        throw runtime_error("fork failed");

    if (pid == 0) {
        cout << "formatting " << dev << endl;
        char *path = strdup(dev.c_str());
        execlp("mkfs.ext2", "-q", path, (char*) NULL);
    }

    int stat;
    if (waitpid(pid, &stat, 0) != pid || stat != 0)
        throw runtime_error("mkfs failed " + to_string(errno));
}

int main() {
    install_signal_handlers();

    try {
        sparse_file store(32 * 1024 * 1024);
        loopback lo(store);
        lvm_handle lh;
        volume_group vg(lh, lo);
        spinner_volume vol0(vg, "vol0", 8 * 1024 * 1024);

        mkfs(vol0.path());

        cout << "go! " << vol0.path() << endl;
        sleep(300);

        cout << "success" << endl;
        return 0;
    } catch (const exception &e) {
        cout << "error: " << e.what() << endl;
        return 1;
    }
}
