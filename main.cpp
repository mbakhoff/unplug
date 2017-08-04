#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <vector>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <linux/loop.h>
#include <libmnl/libmnl.h>
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
#include <lvm2app.h>
#include <pwd.h>

using namespace std;

#define dump_error(fn) \
    printf("%s: %s (%d) #%d\n", fn, strerror(errno), errno, __LINE__);

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
            cout << "formatting " << dev_path << endl;
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
        cout << "mounting " + from + " to " + to << endl;
        if (mount(from.c_str(), to.c_str(), fstype.c_str(), flags, NULL)) {
            rmdirs(created_dirs);
            throw runtime_error("mount(" + from + ", " + to + ") failed: " + to_string(errno));
        }
    }

    virtual ~mountpoint() {
        //if (umount2(to.c_str(), MNT_DETACH)) {
        if (umount(to.c_str())) {
            cerr << "failed to unmount " << to << endl;
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

struct veth_pair {

    string host, container;

    veth_pair(pid_t container_pid) {
        host = "up" + to_string(getpid());
        container = host + "c";

        char buf[MNL_SOCKET_BUFFER_SIZE];
        memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

        nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        nlh->nlmsg_type = RTM_NEWLINK;
        nlh->nlmsg_seq = time(NULL);

        ifinfomsg *ifm = (ifinfomsg*) mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
        ifm->ifi_family = AF_UNSPEC;
        ifm->ifi_change = 0;
        ifm->ifi_flags = 0;

        mnl_attr_put_str(nlh, IFLA_IFNAME, host.c_str());

        nlattr *linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
        mnl_attr_put_str(nlh, IFLA_INFO_KIND, "veth");

        nlattr *data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
        nlattr *veth_peer = mnl_attr_nest_start(nlh, VETH_INFO_PEER);

        ifinfomsg *ifm2 = (ifinfomsg*) mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm2));
        ifm2->ifi_family = AF_UNSPEC;
        ifm2->ifi_change = 0;
        ifm2->ifi_flags = 0;

        mnl_attr_put_str(nlh, IFLA_IFNAME, container.c_str());
        mnl_attr_put_u32(nlh, IFLA_NET_NS_PID, container_pid);

        mnl_attr_nest_end(nlh, veth_peer);
        mnl_attr_nest_end(nlh, data);
        mnl_attr_nest_end(nlh, linkinfo);

        struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
        if (nl == NULL) {
            perror("mnl_socket_open");
            throw runtime_error("mnl_socket_open");
        }
        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
            perror("mnl_socket_bind");
            throw runtime_error("mnl_socket_bind");
        }
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            throw runtime_error("mnl_socket_sendto");
        }

        char resp_buf[MNL_SOCKET_BUFFER_SIZE];
        memset(resp_buf, 0, MNL_SOCKET_BUFFER_SIZE);

        ssize_t rx = mnl_socket_recvfrom(nl, resp_buf, sizeof(resp_buf));
        if (rx == -1) {
            perror("mnl_socket_recvfrom");
            throw runtime_error("mnl_socket_recvfrom");
        }

        mnl_socket_close(nl);

        nlmsghdr *resp = (nlmsghdr*) resp_buf;
        if (resp->nlmsg_type != NLMSG_ERROR) {
            throw runtime_error("unexpected response " + to_string(resp->nlmsg_type));
        }
        nlmsgerr *resp_msg = (nlmsgerr*) mnl_nlmsg_get_payload(resp);
        if (resp_msg->error != 0) {
            throw runtime_error("status " + to_string(resp_msg->error));
        }
    }

    virtual ~veth_pair() {
        char buf[MNL_SOCKET_BUFFER_SIZE];
        memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

        nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        nlh->nlmsg_type = RTM_DELLINK;
        nlh->nlmsg_seq = time(NULL);

        ifinfomsg *ifm = (ifinfomsg*) mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
        ifm->ifi_family = AF_UNSPEC;
        ifm->ifi_change = 0;
        ifm->ifi_flags = 0;

        mnl_attr_put_str(nlh, IFLA_IFNAME, host.c_str());

        struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
        if (nl == NULL) {
            perror("mnl_socket_open");
            return;
        }
        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
            perror("mnl_socket_bind");
            return;
        }
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            perror("mnl_socket_sendto");
            return;
        }

        char resp_buf[MNL_SOCKET_BUFFER_SIZE];
        memset(resp_buf, 0, MNL_SOCKET_BUFFER_SIZE);

        ssize_t rx = mnl_socket_recvfrom(nl, resp_buf, sizeof(resp_buf));
        if (rx == -1) {
            perror("mnl_socket_recvfrom");
            return;
        }

        mnl_socket_close(nl);

        nlmsghdr *resp = (nlmsghdr*) resp_buf;
        if (resp->nlmsg_type != NLMSG_ERROR) {
            cerr << ("unexpected response " + to_string(resp->nlmsg_type)) << endl;
        }
        nlmsgerr *resp_msg = (nlmsgerr*) mnl_nlmsg_get_payload(resp);
        if (resp_msg->error != 0) {
            cerr << ("status " + to_string(resp_msg->error)) << endl;;
        }
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

    if (setgid(gid) || setuid(uid)) {
        perror("failed to drop privileges");
        return -1;
    }

    return 0;
}

void run_unplugged() {
    pid_t pid = fork();
    if (pid == -1)
        throw runtime_error("fork failed");

    if (pid == 0) {
        if (change_user("mart")) // TODO configure
            exit(1);

        execlp("bash", "bash", (char*) NULL);
    }

    waitpid(pid, NULL, 0);
}

void run_child(mountpoint &m) {
    pid_t pid = fork();
    if (pid == -1)
        throw runtime_error("fork failed");

    if (pid == 0) {
        if (unshare(CLONE_NEWNS | CLONE_NEWNET)) {
            perror("unshare failed");
            exit(1);
        }

        // MS_PRIVATE ensures our overlays don't propagate to the original mount namespace
        if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
            perror("failed to mount root private");
            exit(1);
        }

        /* scope for destructors */ {
            mountpoint vol0_bind(m.to, "/opt", "none", MS_BIND);
            run_unplugged();
        }
        exit(0);
    }

    sleep(1); // TODO sync with pipe
    veth_pair veth(pid);

    int stat;
    int result = waitpid(pid, &stat, 0);
    if (result != pid) {
        throw runtime_error(
            string("waiting for the child process failed")
            + " errno=" + to_string(errno)
            + " stat=" + to_string(stat)
            + " result=" + to_string(result)
        );
    }
}

int main() {
    install_signal_handlers();

    try {
        sparse_file store(32 * 1024 * 1024);
        loopback lo(store);
        lvm_handle lh;
        volume_group vg(lh, lo);
        unplug_volume vol0(vg, "vol0", 8 * 1024 * 1024);

        vol0.mkfs_ext2();
        mountpoint vol0_public(vol0.path(), "/tmp/unplug/vol0", "ext2");

        run_child(vol0_public);

        cout << "success" << endl;
        return 0;
    } catch (const exception &e) {
        cout << "error: " << e.what() << endl;
        return 1;
    }
}
