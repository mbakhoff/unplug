#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <vector>

#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/rule.h>
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
#include <lvm2app.h>
#include <pwd.h>

using std::string;
using std::vector;
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
    FILE *ip_forward = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (ip_forward == NULL)
        throw runtime_error("ip_forward");
    char enable = '1';
    int w = fwrite(&enable, 1, 1, ip_forward);
    if (fclose(ip_forward) || w != 1)
        throw runtime_error("ip_forward");
}

struct unplug_config {
    string runas;
    vector<string> isolated_dirs;
    vector<string> argv;
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
                throw runtime_error("failed to create " + dir);
            }
        }

        path = dir + "/store-" + to_string(getpid());

        fd = open(path.c_str(), O_RDWR | O_CREAT);
        if (fd == -1) {
            dump_error("open");
            throw runtime_error("failed to create store (open) " + path);
        }

        FILE *file = fdopen(fd, "w");
        if (fseek(file, size - 1, SEEK_SET)) {
            dump_error("fseek");
            throw runtime_error("failed to create store (seek) " + path);
        }
        char null_byte = 0;
        if (fwrite(&null_byte, 1, 1, file) != 1) {
            dump_error("fwrite");
            throw runtime_error("failed to create store (write) " + path);
        }
        if (fflush(file)) {
            dump_error("fflush");
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
        return "unplug" + to_string(getpid());
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

struct unplug_volume {

    volume_group &vg_info;
    string name;
    char *uuid;

    unplug_volume(volume_group &vg_info, const string &name, uint64_t size) : vg_info(vg_info) {
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

    void mkfs_ext2() {
        string dev_path = path();
        pid_t pid = fork();
        if (pid == -1)
            throw runtime_error("fork failed");

        if (pid == 0) {
            printf("formatting %s\n", dev_path.c_str());
            execlp("mkfs.ext2", "mkfs.ext2", "-q", dev_path.c_str(), (char*) NULL);
        }

        int stat;
        if (waitpid(pid, &stat, 0) != pid || stat != 0)
            throw runtime_error("mkfs failed " + to_string(errno));
    }

    virtual ~unplug_volume() {
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

struct mountpoint {

    vector<string> created_dirs;
    string from, to;

    mountpoint(const string &from, const string &to, const string &fstype, uint64_t flags = 0) : from(from), to(to) {
        mkdirs(to, created_dirs);
        printf("mounting %s to %s\n", from.c_str(), to.c_str());
        if (mount(from.c_str(), to.c_str(), fstype.c_str(), flags, NULL)) {
            rmdirs(created_dirs);
            throw runtime_error("mount(" + from + ", " + to + ") failed: " + to_string(errno));
        }
    }

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
            size_t offset = 1;
            while (offset < path.length()) {
                size_t pos = path.find('/', offset);
                if (pos == string::npos) {
                    pos = path.length();
                }
                string parent = path.substr(0, pos);
                if (mkdir(parent.c_str(), 0755)) {
                    if (errno != EEXIST)
                        throw runtime_error("failed to mkdir " + path);
                } else {
                    created.push_back(parent);
                }
                offset = pos + 1;
            }

            struct stat s;
            if (stat(path.c_str(), &s) || (s.st_mode & S_IFDIR) != S_IFDIR) {
                throw runtime_error(path + " not a directory");
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

    string subnet_addr() {
        in_addr addr;
        addr.s_addr = (10) | ((host_pid % UINT16_MAX) << 8);
        return inet_ntoa(addr);
    }

    void configure_host() {
        int err;

        rtnl_link *link;
        if ((err = rtnl_link_get_kernel(nl_handle.sk, 0, host.c_str(), &link)) < 0) {
            nl_perror(err, "Unable to refresh link");
            throw runtime_error("rtnl_link_get_kernel");
        }

        uint32_t ip_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (1 << 24);
        nl_addr *ip = nl_addr_build(AF_INET, &ip_raw, sizeof(ip_raw));
        nl_addr_set_prefixlen(ip, 30);

        rtnl_addr *addr = rtnl_addr_alloc();
        rtnl_addr_set_family(addr, AF_INET);
        rtnl_addr_set_link(addr, link);
        rtnl_addr_set_local(addr, ip);

        if ((err = rtnl_addr_add(nl_handle.sk, addr, 0)) < 0) {
            nl_perror(err, "Unable to set link ip");
            throw runtime_error("rtnl_addr_add");
        }

        rtnl_link *req = rtnl_link_alloc();
        rtnl_link_set_flags(req, IFF_UP | IFF_RUNNING);

        if ((err = rtnl_link_change(nl_handle.sk, link, req, 0)) < 0) {
            nl_perror(err, "Unable to set link up");
            throw runtime_error("rtnl_link_change");
        }

        string nat_command = "iptables -t nat -A POSTROUTING -s " + subnet_addr() + "/30 -j MASQUERADE";
        if (system(nat_command.c_str()))
            throw runtime_error("MASQUERADE");

        rtnl_link_put(req);
        rtnl_link_put(link);
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

    void add_gateway(nl_sock *sk) {
        int err;

        uint32_t gw_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (1 << 24);
        nl_addr *gw_ip = nl_addr_build(AF_INET, &gw_raw, sizeof(gw_raw));

        nl_addr *gw_target;
        nl_addr_parse("0.0.0.0/0", AF_INET, &gw_target);

        rtnl_route *route_gw = rtnl_route_alloc();
        rtnl_route_set_dst(route_gw, gw_target);

        rtnl_nexthop *nh = rtnl_route_nh_alloc();
        rtnl_route_nh_set_gateway(nh, gw_ip);
        rtnl_route_add_nexthop(route_gw, nh);

        if ((err = rtnl_route_add(sk, route_gw, NLM_F_CREATE)) < 0) {
            nl_perror(err, "Unable to add default gateway");
            throw runtime_error("rtnl_route_add");
        }

        rtnl_route_put(route_gw);
        nl_addr_put(gw_ip);
        nl_addr_put(gw_target);
    }

    void configure_container() {
        int err;

        // TODO unhack
        nl_sock *sk = nl_socket_alloc();
        if ((err = nl_connect(sk, NETLINK_ROUTE)) < 0) {
            nl_perror(err, "Unable to connect socket");
            throw runtime_error("nl_connect");
        }

        rtnl_link *lo;
        if ((err = rtnl_link_get_kernel(sk, 0, "lo", &lo)) < 0) {
            nl_perror(err, "Unable to refresh lo");
            throw runtime_error("rtnl_link_get_kernel");
        }
        rtnl_link *req_lo = rtnl_link_alloc();
        rtnl_link_set_flags(req_lo, IFF_UP | IFF_RUNNING);
        if ((err = rtnl_link_change(sk, lo, req_lo, 0)) < 0) {
            nl_perror(err, "Unable to set lo up");
            throw runtime_error("rtnl_link_change");
        }
        rtnl_link_put(lo);

        rtnl_link *peer;
        if ((err = rtnl_link_get_kernel(sk, 0, container.c_str(), &peer)) < 0) {
            nl_perror(err, "Unable to refresh peer");
            throw runtime_error("rtnl_link_get_kernel");
        }

        uint32_t ip_raw = (10) | ((host_pid % UINT16_MAX) << 8) | (2 << 24);
        nl_addr *ip = nl_addr_build(AF_INET, &ip_raw, sizeof(ip_raw));
        nl_addr_set_prefixlen(ip, 30);

        rtnl_addr *addr = rtnl_addr_alloc();
        rtnl_addr_set_family(addr, AF_INET);
        rtnl_addr_set_link(addr, peer);
        rtnl_addr_set_local(addr, ip);

        if ((err = rtnl_addr_add(sk, addr, 0)) < 0) {
            nl_perror(err, "Unable to set peer ip");
            throw runtime_error("rtnl_addr_add");
        }

        rtnl_link *req = rtnl_link_alloc();
        rtnl_link_set_flags(req, IFF_UP | IFF_RUNNING);

        if ((err = rtnl_link_change(sk, peer, req, 0)) < 0) {
            nl_perror(err, "Unable to set peer up");
            throw runtime_error("rtnl_link_change");
        }

        add_gateway(sk);

        rtnl_link_put(req);
        rtnl_link_put(peer);
        nl_close(sk);
    }

    virtual ~veth_pair() {
        string nat_cleanup = "iptables -t nat -D POSTROUTING -s " + subnet_addr() + "/30 -j MASQUERADE";
        system(nat_cleanup.c_str());

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
        throw runtime_error("fork failed (unplugged)");

    if (pid == 0) {
        if (change_user(cfg.runas))
            exit(1);

        int argc = cfg.argv.size();
        char *cmd[argc + 1];
        for (int i = 0; i < argc; i++) {
            cmd[i] = strdup(cfg.argv[i].c_str());
        }
        cmd[argc] = NULL;

        execvp(cmd[0], cmd);
    }

    waitpid(pid, NULL, 0);
}

void run_child(unplug_config &cfg, mountpoint &m) {

    nl_sock_handle nl_handle;
    veth_pair veth(nl_handle);
    veth.configure_host();

    pid_t pid = fork();
    if (pid == -1)
        throw runtime_error("fork failed");

    if (pid == 0) {
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
                mountpoint vol0_bind(m.to, "/opt", "none", MS_BIND);
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
        perror("waiting for child");
        throw runtime_error("waitpid");
    }
}

int main(int argc, char **argv) {
    unplug_config cfg;
    cfg.runas = "mart";
    cfg.isolated_dirs.push_back("/opt");
    for (int i = 1; i < argc; i++) {
        cfg.argv.push_back(argv[i]);
    }
    if (cfg.argv.empty()) {
        printf("no command\n");
        exit(1);
    }

    install_signal_handlers();
    enable_ip_forward();

    try {
        sparse_file store(32 * 1024 * 1024);
        loopback lo(store);
        lvm_handle lh;
        volume_group vg(lh, lo);
        unplug_volume vol0(vg, "vol0", 8 * 1024 * 1024);

        vol0.mkfs_ext2();
        mountpoint vol0_public(vol0.path(), "/tmp/unplug/vol0", "ext2");

        run_child(cfg, vol0_public);

        printf("success\n");
        return 0;
    } catch (const exception &e) {
        printf("error: %s\n", e.what());
        return 1;
    }
}
