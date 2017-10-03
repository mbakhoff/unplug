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

int exit_signal_caught = 0;

#define dump_error(fn) \
    fprintf(stderr, "%s: %s (%d) #%d\n", fn, strerror(errno), errno, __LINE__);

void on_close_signal(int sig) {
    exit_signal_caught = sig;
}

void install_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_close_signal;
    sigfillset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL))
        fail("sigaction");
    if (sigaction(SIGTERM, &sa, NULL))
        fail("sigaction");
}

void clear_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGINT, &sa, NULL))
        fail("sigaction");
    if (sigaction(SIGTERM, &sa, NULL))
        fail("sigaction");
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
    string workspace;
    vector<string> isolated_dirs;
    vector<string> cmd;

    unplug_config(int argc, char **argv) {
        int i = 1;
        while (i < argc - 1) {
            if (strstr(argv[i], "-u") == argv[i]) {
                runas = argv[i + 1];
                i += 2;
            }
            else if (strstr(argv[i], "-w") == argv[i]) {
                workspace = argv[i + 1];
                while (!workspace.empty() && workspace.back() == '/')
                    workspace.pop_back();
                i += 2;
            }
            else if (strstr(argv[i], "-d") == argv[i]) {
                string dir = argv[i + 1];
                while (!dir.empty() && dir.back() == '/')
                    dir.pop_back();
                isolated_dirs.push_back(dir);
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

struct workspace {

    string root;

    workspace(const unplug_config &cfg) {
        if (cfg.workspace.empty()) {
            char *envhome = getenv("HOME");
            if (envhome == NULL)
                fail("workspace not configured and HOME not set");
            root = string() + envhome + "/.unplug/" + to_string(getpid());
        } else {
            root = cfg.workspace + "/" + to_string(getpid());
        }
        for (const string &dir : ancestors(root)) {
            if (mkdir(dir.c_str(), 0755) && errno != EEXIST) {
                fail("mkdir " + dir);
            }
        }
    }

    workspace(const workspace &src) = delete;

    virtual ~workspace() {
        try {
            exec({"rm", "-rf", root});
        } catch (const exception &e) {
            fprintf(stderr, "failed to clean workspace %s: %s\n", root.c_str(), e.what());
        }
    }
};

struct mount_bind {

    vector<string> created_dirs;
    string from, to;

    mount_bind(const string &from, const string &to) : from(from), to(to) {
        mkdirs(to, created_dirs);
        printf("mounting %s to %s\n", from.c_str(), to.c_str());
        if (mount(from.c_str(), to.c_str(), "none", MS_BIND, NULL)) {
            rmdirs(created_dirs);
            fail("mount from=" + from + " to=" + to);
        }
    }

    mount_bind(const mount_bind &src) = delete;

    virtual ~mount_bind() {
        //if (umount2(to.c_str(), MNT_DETACH)) {
        if (umount(to.c_str())) {
            fprintf(stderr, "failed to unmount %s\n", to.c_str());
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

    nl_sock_handle(const nl_sock_handle &src) = delete;

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
        exec({"iptables", "-w", "10", "-t", "nat", "-I", "POSTROUTING", "1", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
        exec({"iptables", "-w", "10", "-I", "FORWARD", "1", "-i", host, "-j", "ACCEPT"});
        exec({"iptables", "-w", "10", "-I", "FORWARD", "1", "-o", host, "-j", "ACCEPT"});
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
            exec({"iptables", "-w", "10", "-D", "FORWARD", "-i", host, "-j", "ACCEPT"});
            exec({"iptables", "-w", "10", "-D", "FORWARD", "-o", host, "-j", "ACCEPT"});
        } catch (const exception &e) {
            perror(e.what());
        }
        try {
            exec({"iptables", "-w", "10", "-t", "nat", "-D", "POSTROUTING", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
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

string gen_cgroup_name() {
    return "/sys/fs/cgroup/cpu/unplug-" + to_string(getpid());
}

struct cpu_cgroup {

    string dir;

    cpu_cgroup(): dir(gen_cgroup_name()) {
        if (mkdir(dir.c_str(), 0755))
            fail("mkdir " + dir);
    }

    cpu_cgroup(const cpu_cgroup &src) = delete;

    void add_pid(pid_t pid) {
        file_write(dir + "/cgroup.procs", to_string(pid));
    }

    vector<pid_t> list() {
        vector<pid_t> result;
        string procs = file_read_fully(dir + "/cgroup.procs");
        int offset = 0;
        while (true) {
            size_t nl = procs.find_first_of('\n', offset);
            if (nl == string::npos)
                break;
            string pid = procs.substr(offset, nl - offset);
            result.push_back(std::stoi(pid));
            offset = nl + 1;
        }
        return result;
    }

    virtual ~cpu_cgroup() {
        if (rmdir(dir.c_str()))
            fprintf(stderr, "failed to clean up cgroup\n");
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

void await_container(pid_t pid) {
    while (true) {
        if (exit_signal_caught) {
            printf("caught signal %d, propagating\n", exit_signal_caught);
            kill(pid, exit_signal_caught);
        }
        int result = waitpid(pid, NULL, 0);
        if (result == pid)
            break;
        if (errno == EINTR)
            continue;
        fail("waiting for child");
    }
}

void kill_cgroup(cpu_cgroup &tracked_cgroup) {
    for (int ttl = 15; ttl >= 0; ttl--) {
        vector<pid_t> descendants = tracked_cgroup.list();
        if (tracked_cgroup.list().empty()) {
            break;
        }

        int sig = ttl > 0 ? SIGTERM : SIGKILL;
        for (pid_t descendant : descendants) {
            printf("kill -%d %d\n", sig, descendant);
            kill(descendant, sig);
            if (sig == SIGKILL) {
                waitpid(descendant, NULL, 0);
            }
        }
        sleep(1);
    }
}

void await_command(pid_t pid, cpu_cgroup &tracked_cgroup) {
    while (true) {
        if (exit_signal_caught)
            break;
        int result = waitpid(pid, NULL, 0);
        if (result == pid)
            break;
        if (errno == EINTR)
            continue;
        fail("waiting for child");
    }

    printf("terminating command cgroup\n");
    kill_cgroup(tracked_cgroup);
}

void run_unplugged(unplug_config &cfg, cpu_cgroup &tracked_cgroup) {
    if (exit_signal_caught)
        return;

    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed (unplugged)");

    if (pid == 0) {
        clear_signal_handlers();

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

    tracked_cgroup.add_pid(pid);
    await_command(pid, tracked_cgroup);
}

void run_child(unplug_config &cfg, workspace &ws) {
    if (exit_signal_caught)
        return;

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
                cpu_cgroup tracked_cgroup;
                vector<unique_ptr<mount_bind>> binds;
                for (string isolated : cfg.isolated_dirs) {
                    string layer_dir = ws.root + isolated;
                    binds.push_back(unique_ptr<mount_bind>(new mount_bind(layer_dir, isolated)));
                }
                run_unplugged(cfg, tracked_cgroup);
            }

            printf("container done\n");
            exit(0);
        } catch (const exception &e) {
            fprintf(stderr, "exception in fork: %s\n", e.what());
            exit(1);
        }
    }

    await_container(pid);
}

void clone_isolated(workspace &ws, vector<string> &sources) {
    for (string &source : sources) {
        string target = ws.root + source;
        string target_parent = target.substr(0, target.find_last_of("/"));

        printf("cloning %s -> %s\n", source.c_str(), ws.root.c_str());
        exec({"mkdir", "-p", target_parent});
        exec({"cp", "-a", source, target_parent});
    }
}

void verify_dirs(const vector<string> &dirs) {
    for (const string &dir : dirs) {
        if (dir.empty())
            fail("isolated dir cannot be empty");
        if (dir.front() != '/')
            fail("isolated dir must be an absolute path: " + dir);
        if (is_link(dir))
            fail("isolated dir must not be a link: " + dir);
        if (starts_with(dir, "/proc/") || dir.compare("/proc") == 0 ||
                starts_with(dir, "/sys/") || dir.compare("/sys") == 0 ||
                starts_with(dir, "/dev/") || dir.compare("/dev") == 0) {
            fail("isolated dir cannot be in one of /proc /sys /dev: " + dir);
        }
    }
}

int main(int argc, char **argv) {
    unplug_config cfg(argc, argv);
    if (cfg.cmd.empty()) {        
        printf("usage: unplug [-u username] [-w workspace_abs_path] [-d abs_path]* <command ...>\n");
        printf("see https://github.com/mbakhoff/unplug for sources\n");
        exit(1);
    }

    verify_dirs(cfg.isolated_dirs);

    install_signal_handlers();
    enable_ip_forward();

    try {
        workspace ws(cfg);
        clone_isolated(ws, cfg.isolated_dirs);

        run_child(cfg, ws);

        printf("unplug finished\n");
        return 0;
    } catch (const exception &e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
