#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.h"

using std::runtime_error;
using std::to_string;


int await_child(pid_t pid) {
    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) != pid)
        fail("waitpid");

    signals_drain_one(SIGCHLD);
    return wstatus;
}

int await_child_interruptibly(pid_t pid) {
    sigset_t set;
    sigfillset(&set);
    if (sigwaitinfo(&set, NULL) != SIGCHLD) {
        fprintf(stderr, "caught signal, terminating child\n");
        kill(pid, SIGTERM);
    }

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) != pid)
        fail("waitpid");

    return wstatus;
}

void signals_block() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
        fail("sigprocmask");
    }
}

void signals_unblock() {
    sigset_t mask;
    sigemptyset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, NULL)) {
        fail("sigprocmask");
    }
}

bool signals_drain_set(sigset_t *set) {
    timespec ts;
    ts.tv_sec = ts.tv_nsec = 0;

    bool any_cleared = false;
    while (sigtimedwait(set, NULL, &ts) != -1) {
        any_cleared = true;
    }
    if (errno != EAGAIN) {
        fail("sigtimedwait");
    }
    errno = 0;

    return any_cleared;
}

bool signals_drain() {
    sigset_t set;
    sigfillset(&set);
    return signals_drain_set(&set);
}

bool signals_drain_one(int signo) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signo);
    return signals_drain_set(&set);
}

string strip_dir(const string &path) {
    size_t pos = path.find_last_of('/');
    return pos == string::npos || pos == path.length() ? path : path.substr(pos + 1);
}

errno_error::errno_error(const string &message, const string &file, long line): runtime_error(message) {
    this->what_message = message + " (" + strip_dir(file) + ":" + to_string(line) + " errno " + to_string(errno) + ": " + strerror(errno) + ")";
}

const char* errno_error::what() const noexcept {
    return this->what_message.c_str();
}

void file_write(const string &path, const string &data) {
    FILE *fh = fopen(path.c_str(), "w");
    if (fh == NULL) {
        fail("writing " + path);
    }

    if (!data.empty()) {
        size_t total = data.length();
        if (fwrite(data.c_str(), 1, total, fh) != total) {
            fclose(fh);
            fail("writing " + path);
        }
    }

    if (fclose(fh)) {
        fail("writing " + path);
    }
}

string file_read_fully(const string &path) {
    FILE *fh = fopen(path.c_str(), "r");
    if (fh == NULL) {
        fail("reading " + path);
    }

    string result;
    char buf[1024];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), fh)) >= 0) {
        if (ferror(fh))
            fail("reading " + path);
        result.append(buf, r);
        if (feof(fh))
            break;
    }

    if (fclose(fh)) {
        fail("reading " + path);
    }

    return result;
}

pipe_latch::pipe_latch() {
    if (pipe(pipefd) == -1)
        fail("pipe");
}

void pipe_latch::release() {
    char buf = 1;
    if (write(pipefd[1], &buf, sizeof(buf)) != sizeof(buf))
        fail("latch release");
    close(pipefd[0]);
    close(pipefd[1]);
}

void pipe_latch::await() {
    char buf = 0;
    if (read(pipefd[0], &buf, sizeof(buf)) != sizeof(buf))
        fail("latch await");
    close(pipefd[0]);
    close(pipefd[1]);
}

void do_exec(bool interruptible, std::initializer_list<string> cmd) {
    string full_cmd;
    for (const string &s : cmd) {
        full_cmd += s;
        full_cmd += " ";
    }

    pipe_latch latch;

    pid_t pid = fork();
    if (pid == -1)
        fail("fork");

    if (pid == 0) {
        try {
            signals_unblock();
            fclose(stdin);

            latch.release();

            int argc = cmd.size();
            char *ccmd[argc + 1];
            int i = 0;
            for (const string &s : cmd) {
                ccmd[i++] = strdup(s.c_str());
            }
            ccmd[argc] = NULL;

            if (execvp(ccmd[0], ccmd)) {
                dump_error("execvp");
                exit(1);
            }
        } catch (const std::exception &e) {
            fprintf(stderr, "FATAL (do_exec): %s\n", e.what());
            exit(1);
        }
    }

    latch.await();

    int wstatus = interruptible
            ? await_child_interruptibly(pid)
            : await_child(pid);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
        throw runtime_error("exec failed: " + full_cmd);
}

void exec(std::initializer_list<string> cmd) {
    do_exec(false, cmd);
}

void exec_interruptibly(std::initializer_list<string> cmd) {
    if (signals_drain())
        fail("signal");
    do_exec(true, cmd);
}

bool is_link(const string &path) {
    struct stat s;
    if (lstat(path.c_str(), &s)) {
        fail("lstat " + path);
    }
    return (s.st_mode & S_IFLNK) == S_IFLNK;
}

bool starts_with(const string &a, const string &b) {
    if (a.length() < b.length())
        return false;
    return a.substr(0, b.length()).compare(b) == 0;
}

vector<string> split(const string &s, char separator) {
    vector<string> result;
    int offset = 0;
    while (true) {
        size_t sep_pos = s.find_first_of(separator, offset);
        result.push_back(s.substr(offset, sep_pos - offset));
        if (sep_pos == string::npos)
            break;
        offset = sep_pos + 1;
    }
    return result;
}

string ip_to_string(uint32_t ip) {
    in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

vector<string> ancestors(const string &path) {
    vector<string> result;
    size_t offset = 1;
    while (offset < path.length()) {
        size_t pos = path.find('/', offset);
        if (pos == string::npos) {
            pos = path.length();
        }
        result.push_back(path.substr(0, pos));
        offset = pos + 1;
    }
    return result;
}
