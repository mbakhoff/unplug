#include <cstring>
#include <string>
#include <stdexcept>
#include <vector>
#include <memory>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
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

struct unplug_config {
    bool usage = false;
    string runas;
    string workspace;
    vector<uint32_t> port_forwards;
    vector<string> isolated_dirs;
    vector<string> cmd;

    unplug_config(int argc, char **argv) {
        int i = 1;
        while (i < argc) {
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
            else if (strstr(argv[i], "-f") == argv[i]) {
                long port = std::stol(argv[i + 1]);
                if (port < 0 || port > UINT32_MAX)
                    throw runtime_error("port out of range: " + port);
                port_forwards.push_back((uint32_t) port);
                i += 2;
            }
            else if (strstr(argv[i], "-h") == argv[i] ||
                     strstr(argv[i], "--help") == argv[i]) {
                usage = true;
                i += 1;
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
        if (!cfg.runas.empty()) {
            struct passwd *pw = getpwnam(cfg.runas.c_str());
            if (pw == NULL)
                fail("no such user: " + cfg.runas);
            if (chown(root.c_str(), pw->pw_uid, pw->pw_gid))
                fail("chown workspace");
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

    string from, to;

    mount_bind(const string &from, const string &to) : from(from), to(to) {
        printf("mounting %s to %s\n", from.c_str(), to.c_str());
        if (mount(from.c_str(), to.c_str(), "none", MS_BIND, NULL)) {
            fail("mount from=" + from + " to=" + to);
        }
    }

    mount_bind(const mount_bind &src) = delete;

    virtual ~mount_bind() {
        if (umount(to.c_str())) {
            fprintf(stderr, "failed to unmount %s\n", to.c_str());
        }
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
    unplug_config &cfg;
    string ifname_host, ifname_container;
    pid_t host_pid;

    veth_pair(nl_sock_handle &nl_handle, unplug_config &cfg) : nl_handle(nl_handle), cfg(cfg) {
        ifname_host = "up" + to_string(getpid());
        ifname_container = ifname_host + "c";
        host_pid = getpid();

        rtnl_link *link = rtnl_link_veth_alloc();
        rtnl_link_set_name(link, ifname_host.c_str());

        rtnl_link *peer = rtnl_link_veth_get_peer(link);
        rtnl_link_set_name(peer, ifname_container.c_str());

        int err;
        if ((err = rtnl_link_add(nl_handle.sk, link, NLM_F_CREATE | NLM_F_EXCL)) < 0) {
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
        exec({"ip", "address", "add", ip_to_string(host_raw) + "/30", "dev", ifname_host});
        exec({"ip", "link", "set", "dev", ifname_host, "up"});
        exec({"iptables", "-w", "10", "-t", "nat", "-I", "POSTROUTING", "1", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
        exec({"iptables", "-w", "10", "-I", "FORWARD", "1", "-i", ifname_host, "-j", "ACCEPT"});
        exec({"iptables", "-w", "10", "-I", "FORWARD", "1", "-o", ifname_host, "-j", "ACCEPT"});
    }

    void assign_to_container_ns() {
        int err;

        rtnl_link *peer;
        // nl_handle is from the original ns -> we can see interfaces from there
        if ((err = rtnl_link_get_kernel(nl_handle.sk, 0, ifname_container.c_str(), &peer)) < 0) {
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
        exec({"ip", "address", "add", ip_to_string(container_raw) + "/30", "dev", ifname_container});
        exec({"ip", "link", "set", "dev", "lo", "up"});
        exec({"ip", "link", "set", "dev", ifname_container, "up"});
        exec({"ip", "route", "add", "0.0.0.0/0", "via", ip_to_string(gw_raw)});
    }

    void setup_port_forwarding() {
        if (cfg.port_forwards.empty())
            return;
        string host_ip = ip_to_string(((10) | ((host_pid % UINT16_MAX) << 8) | (1 << 24)));
        file_write("/proc/sys/net/ipv4/conf/all/route_localnet", "1");
        exec({"iptables", "-w", "10", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"});
        for (uint32_t port : cfg.port_forwards) {
            exec({"iptables", "-w", "10", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", to_string(port), "-j", "DNAT", "--to-destination", host_ip});
        }
    }

    virtual ~veth_pair() {
        uint32_t subnet_raw = (10) | ((host_pid % UINT16_MAX) << 8);
        try {
            exec({"iptables", "-w", "10", "-D", "FORWARD", "-i", ifname_host, "-j", "ACCEPT"});
            exec({"iptables", "-w", "10", "-D", "FORWARD", "-o", ifname_host, "-j", "ACCEPT"});
        } catch (const exception &e) {
            perror(e.what());
        }
        try {
            exec({"iptables", "-w", "10", "-t", "nat", "-D", "POSTROUTING", "-s", ip_to_string(subnet_raw) + "/30", "-j", "MASQUERADE"});
        } catch (const exception &e) {
            perror(e.what());
        }
    }
};

struct cpu_cgroup {

    string dir;

    cpu_cgroup(): dir(gen_cgroup_name()) {
        if (mkdir(dir.c_str(), 0755))
            fail("mkdir " + dir);
    }

    cpu_cgroup(const cpu_cgroup &src) = delete;

    static string gen_cgroup_name() {
        return "/sys/fs/cgroup/cpu/unplug-" + to_string(getpid());
    }

    void add_pid(pid_t pid) {
        file_write(dir + "/cgroup.procs", to_string(pid));
    }

    vector<pid_t> list() {
        string procs = file_read_fully(dir + "/cgroup.procs");
        vector<pid_t> result;
        for (const string &pid : split(procs, '\n')) {
            if (!pid.empty())
                result.push_back(std::stoi(pid));
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

void run_command(unplug_config &cfg, cpu_cgroup &tracked_cgroup) {
    if (exit_signal_caught)
        return;

    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed (unplugged)");

    if (pid == 0) {
        clear_signal_handlers();
        tracked_cgroup.add_pid(getpid());

        if (!cfg.runas.empty() && change_user(cfg.runas))
            exit(1);

        int argc = cfg.cmd.size();
        char *cmd[argc + 1];
        for (int i = 0; i < argc; i++) {
            cmd[i] = strdup(cfg.cmd[i].c_str());
        }
        cmd[argc] = NULL;

        if (execvp(cmd[0], cmd)) {
            dump_error("execvp");
            exit(1);
        }
    }

    await_command(pid, tracked_cgroup);
}

void run_container(unplug_config &cfg, workspace &ws) {
    if (exit_signal_caught)
        return;

    nl_sock_handle nl_handle;
    veth_pair veth(nl_handle, cfg);
    veth.configure_host();

    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed");

    if (pid == 0) {
        string pid_str = to_string(parent);
        setenv("UNPLUG_PID", pid_str.c_str(), 1);

        try {
            if (unshare(CLONE_NEWNET)) {
                perror("CLONE_NEWNET failed");
                exit(1);
            }
            if (!cfg.isolated_dirs.empty()) {
                if (unshare(CLONE_NEWNS)) {
                    perror("CLONE_NEWNS failed");
                    exit(1);
                }
                // MS_PRIVATE ensures our overlays don't propagate to the original mount namespace
                if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
                    perror("failed to mount root private");
                    exit(1);
                }
            }

            veth.assign_to_container_ns();
            veth.configure_container();
            veth.setup_port_forwarding();

            /* scope for destructors */ {
                cpu_cgroup tracked_cgroup;
                vector<unique_ptr<mount_bind>> binds;
                for (string isolated : cfg.isolated_dirs) {
                    string layer_dir = ws.root + isolated;
                    binds.push_back(unique_ptr<mount_bind>(new mount_bind(layer_dir, isolated)));
                }
                run_command(cfg, tracked_cgroup);
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
    if (cfg.usage || cfg.cmd.empty()) {
        printf("usage: unplug [options] <command ...>\n");
        printf("options:\n");
        printf("  -u <user>\t - run command as user\n");
        printf("  -w <path>\t - absolute path of the workspace\n");
        printf("  -d <path>\t - absolute path of an isolated directory (repeatable)\n");
        printf("  -f <port>\t - port to forward to host (repeatable)\n");
        printf("\n");
        printf("see https://github.com/mbakhoff/unplug for sources\n");
        exit(1);
    }

    verify_dirs(cfg.isolated_dirs);

    install_signal_handlers();
    enable_ip_forward();

    try {
        workspace ws(cfg);
        clone_isolated(ws, cfg.isolated_dirs);

        run_container(cfg, ws);

        printf("unplug finished\n");
        return 0;
    } catch (const exception &e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
