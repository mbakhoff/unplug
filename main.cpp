#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <vector>
#include <memory>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "utils.h"

using std::string;
using std::vector;
using std::unique_ptr;
using std::exception;
using std::runtime_error;
using std::to_string;

#define dump_error(fn) \
    printf("%s: %s (%d) #%d\n", fn, strerror(errno), errno, __LINE__);

void on_close_signal(int sig) {
    printf("caught signal %d\n", sig);
}

void install_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_close_signal;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

void enable_ip_forward() {
    file_write("/proc/sys/net/ipv4/ip_forward", "1");
}

void mkfs_ext2(const string &path) {
    if (!is_regular(path)) {
        throw runtime_error(path + " not a file");
    }
    exec({"mkfs.ext2", "-q", path}); // TODO ext4 w/o journal?
}

struct unplug_config {
    string runas;
    vector<string> isolated_dirs;
    vector<string> cmd;

    unplug_config(int argc, char **argv) {
        int i = 1;
        while (i < argc - 1) {
            if (strstr(argv[i], "-u") == argv[i]) {
                runas = argv[i + 1];
                i += 2;
            }
            else if (strstr(argv[i], "-d") == argv[i]) {
                isolated_dirs.push_back(argv[i + 1]);
                i += 2;
            }
            else {
                break;
            }
        }

        while (i < argc) {
            cmd.push_back(argv[i++]);
        }
    }
};

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

        string dir = home + "/.unplug";
        if (mkdir(dir.c_str(), 0755)) {
            if (errno != EEXIST) {
                fail("failed to create " + dir);
            }
        }

        path = dir + "/store-" + to_string(getpid());

        fd = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            fail("failed to create store " + path);
        }

        FILE *file = fdopen(fd, "w");
        if (fseek(file, size - 1, SEEK_SET)) {
            fail("failed to create store " + path);
        }
        char null_byte = 0;
        if (fwrite(&null_byte, 1, 1, file) != 1) {
            fail("failed to create store " + path);
        }
        if (fflush(file)) {
            fail("failed to create store " + path);
        }
    }

    sparse_file(const sparse_file &src) = delete;

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
                fail("failed to create loop device " + path);
            }

            fd = open(path.c_str(), O_RDWR);
            if (fd == -1) {
                unlink(path.c_str());
                printf("trying %s\n", path.c_str());
                dump_error("loopback");
                continue;
            }
            if (ioctl(fd, LOOP_SET_FD, store.fd)) {
                close(fd);
                unlink(path.c_str());
                printf("trying %s\n", path.c_str());
                dump_error("loopback");
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

    loopback(const loopback &src) = delete;

    virtual ~loopback() {
        ioctl(fd, LOOP_CLR_FD);
        close(fd);
        unlink(path.c_str());
    }
};

struct mountpoint {

    vector<string> created_dirs;
    string from, to;

    mountpoint(const string &from, const string &to, const string &fstype, uint64_t flags = 0) : from(from), to(to) {
        mkdirs(to, created_dirs);
        printf("mounting %s to %s\n", from.c_str(), to.c_str());
        if (mount(from.c_str(), to.c_str(), fstype.c_str(), flags, NULL)) {
            rmdirs(created_dirs);
            fail("mount from=" + from + " to=" + to);
        }
    }

    mountpoint(const mountpoint &src) = delete;

    virtual ~mountpoint() {
        //if (umount2(to.c_str(), MNT_DETACH)) {
        if (umount(to.c_str())) {
            printf("failed to unmount %s\n", to.c_str());
        } else {
            rmdirs(created_dirs);
        }
    }

    void mkdirs(const string &path, vector<string> &created) {
        if (path.at(0) != '/')
            throw runtime_error("mountpoint must be absolute path");
        try {
            for (string &ancestor : ancestors(path)) {
                if (mkdir(ancestor.c_str(), 0755)) {
                    if (errno != EEXIST)
                        fail("failed to mkdir " + path);
                } else {
                    created.push_back(ancestor);
                }
            }

            struct stat s;
            if (stat(path.c_str(), &s) || (s.st_mode & S_IFDIR) != S_IFDIR) {
                fail(path + " not a directory");
            }
        } catch (runtime_error &e) {
            rmdirs(created);
            throw e;
        }
    }

    int rmdirs(const vector<string> &dirs) {
        for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
            const string &dir = *it;
            if (rmdir(dir.c_str()))
                return -1;
        }
        return 0;
    }
};

struct nl_sock_handle {

    nl_sock *sk;

    nl_sock_handle() {
        int err;

        sk = nl_socket_alloc();
        if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
            nl_perror(err, "Unable to connect socket");
            throw runtime_error("nl_connect");
        }
    }

    virtual ~nl_sock_handle() {
        nl_close(sk);
    }
};

struct veth_pair {

    nl_sock_handle &nl_handle;
    string host, container;
    pid_t host_pid;

    veth_pair(nl_sock_handle &nl_handle) : nl_handle(nl_handle) {
        host = "up" + to_string(getpid());
        container = host + "c";
        host_pid = getpid();

        rtnl_link *link = rtnl_link_veth_alloc();
        rtnl_link_set_name(link, host.c_str());

        rtnl_link *peer = rtnl_link_veth_get_peer(link);
        rtnl_link_set_name(peer, container.c_str());

        int err;
        if ((err = rtnl_link_add(nl_handle.sk, link, NLM_F_CREATE)) < 0) {
                nl_perror(err, "Unable to add link");
                throw runtime_error("rtnl_link_add");
        }

        rtnl_link_put(link);
        rtnl_link_put(peer);
    }

    veth_pair(const veth_pair &src) = delete;

    void configure_host() {
        uint32_t host_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (1 << 24);
        uint32_t subnet_raw = (10) | ((host_pid % UINT16_MAX) << 8);
        exec({"ip", "address", "add", ip_to_string(host_raw) + "/30", "dev", host});
        exec({"ip", "link", "set", "dev", host, "up"});
        exec({"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
    }

    void assign_to_container_ns() {
        int err;

        rtnl_link *peer;
        // nl_handle is from the original ns -> we can see interfaces from there
        if ((err = rtnl_link_get_kernel(nl_handle.sk, 0, container.c_str(), &peer)) < 0) {
            nl_perror(err, "Unable to refresh peer");
            throw runtime_error("rtnl_link_get_kernel");
        }

        rtnl_link *req = rtnl_link_alloc();
        rtnl_link_set_ns_pid(req, getpid());

        if ((err = rtnl_link_change(nl_handle.sk, peer, req, 0)) < 0) {
            nl_perror(err, "Unable to assign peer ns");
            throw runtime_error("rtnl_link_change");
        }

        rtnl_link_put(req);
        rtnl_link_put(peer);
    }

    void configure_container() {
        uint32_t container_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (2 << 24);
        uint32_t gw_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (1 << 24);
        exec({"ip", "address", "add", ip_to_string(container_raw) + "/30", "dev", container});
        exec({"ip", "link", "set", "dev", "lo", "up"});
        exec({"ip", "link", "set", "dev", container, "up"});
        exec({"ip", "route", "add", "0.0.0.0/0", "via", ip_to_string(gw_raw)});
    }

    virtual ~veth_pair() {
        uint32_t subnet_raw = (10) | ((host_pid % UINT16_MAX) << 8);
        try {
            exec({"iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
        } catch (const exception &e) {
            perror(e.what());
        }

        rtnl_link *link = rtnl_link_alloc();
        rtnl_link_set_name(link, host.c_str());

        int err;
        if ((err = rtnl_link_delete(nl_handle.sk, link)) < 0) {
            nl_perror(err, "Unable to delete link");
            return;
        }

        rtnl_link_put(link);
    }
};

int change_user(const string &user) {
    struct passwd *pw = getpwnam(user.c_str());
    if (pw == NULL) {
        perror("user not found");
        return -1;
    }
    gid_t gid = pw->pw_gid;
    uid_t uid = pw->pw_uid;

    int ngroups = 1024;
    gid_t group_ids[ngroups];
    if (getgrouplist(user.c_str(), gid, group_ids, &ngroups) == -1) {
        perror("too many complementary groups");
        return -1;
    }
    if (setgroups(ngroups, group_ids)) {
        perror("failed to assign complementary groups");
        return -1;
    }

    if (setgid(gid) || setuid(uid)) {
        perror("failed to drop privileges");
        return -1;
    }

    return 0;
}

void run_unplugged(unplug_config &cfg) {
    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed (unplugged)");

    if (pid == 0) {
        if (!cfg.runas.empty() && change_user(cfg.runas))
            exit(1);

        int argc = cfg.cmd.size();
        char *cmd[argc + 1];
        for (int i = 0; i < argc; i++) {
            cmd[i] = strdup(cfg.cmd[i].c_str());
        }
        cmd[argc] = NULL;

        execvp(cmd[0], cmd);
    }

    waitpid(pid, NULL, 0);
}

void run_child(unplug_config &cfg, mountpoint &layer) {

    nl_sock_handle nl_handle;
    veth_pair veth(nl_handle);
    veth.configure_host();

    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed");

    if (pid == 0) {
        string pid_str = to_string(parent);
        setenv("UNPLUG_PID", pid_str.c_str(), 1);

        try {
            if (unshare(CLONE_NEWNS | CLONE_NEWNET)) {
                perror("unshare failed");
                exit(1);
            }

            veth.assign_to_container_ns();
            veth.configure_container();

            // MS_PRIVATE ensures our overlays don't propagate to the original mount namespace
            if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
                perror("failed to mount root private");
                exit(1);
            }

            /* scope for destructors */ {
                vector<unique_ptr<mountpoint>> binds;
                for (string isolated : cfg.isolated_dirs) {
                    string layer_dir = layer.to + isolated;
                    binds.push_back(unique_ptr<mountpoint>(new mountpoint(layer_dir, isolated, "none", MS_BIND)));
                }
                run_unplugged(cfg);
            }

            exit(0);
        } catch (exception &e) {
            printf("exception in fork: %s\n", e.what());
            exit(1);
        }
    }

    int result = waitpid(pid, NULL, 0);
    if (result != pid) {
        fail("waiting for child");
    }
}

void clone_isolated(mountpoint &layer, vector<string> &sources) {
    for (string &source : sources) {
        if (source.empty() || source.at(0) != '/') {
            throw runtime_error("isolated paths must be absolute");
        }
        string target = layer.to + source;
        string target_parent = target.substr(0, target.find_last_of("/"));

        printf("cloning %s -> %s\n", source.c_str(), layer.to.c_str());
        exec({"mkdir", "-p", target_parent});
        exec({"cp", "-a", source, target_parent});
    }
}

uint64_t calculate_store_size(const vector<string> dirs) {
    uint64_t total = 0;
    for (const string &dir : dirs) {
        total += dir_size(dir);
    }

    uint64_t mb128 = 128 * 1024 * 1024;
    if (total < mb128)
        return mb128;

    return total * 1.1 + mb128 * 2;
}

int main(int argc, char **argv) {
    unplug_config cfg(argc, argv);
    if (cfg.cmd.empty()) {
        printf("usage: unplug [-u username] [-d abs_path]* <command ...>\n");
        exit(1);
    }

    install_signal_handlers();
    enable_ip_forward();

    try {
        sparse_file store(calculate_store_size(cfg.isolated_dirs));
        mkfs_ext2(store.path);
        loopback lo(store);

        string layer_path = "/tmp/unplug/" + to_string(getpid());
        mountpoint layer(lo.path, layer_path.c_str(), "ext2");

        clone_isolated(layer, cfg.isolated_dirs);

        run_child(cfg, layer);

        printf("unplug finished\n");
        return 0;
    } catch (const exception &e) {
        printf("error: %s\n", e.what());
        return 1;
    }
}
