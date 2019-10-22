#ifndef UNPLUG_UTILS_H
#define UNPLUG_UTILS_H

#include <string>
#include <vector>
#include <stdexcept>

using std::string;
using std::vector;
using std::runtime_error;

#define fail(message) \
    throw errno_error(message, __FILE__, __LINE__);

#define dump_error(fn) \
    fprintf(stderr, "%s: %s (%d) #%d\n", fn, strerror(errno), errno, __LINE__);

class errno_error: public runtime_error {
    string what_message;
public:
    errno_error(const string &message, const string &file, long line);
    virtual const char* what() const noexcept;
};

struct pipe_latch {
    int pipefd[2];
    pipe_latch();
    void release();
    void await();
};

int await_child_interruptibly(pid_t pid);

void signals_block();
void signals_unblock();
bool signals_drain();
bool signals_drain_one(int signo);

void file_write(const string &path, const string &data);
string file_read_fully(const string &path);
void exec(std::initializer_list<string> cmd);
void exec_interruptibly(std::initializer_list<string> cmd);
bool is_link(const string &path);
bool starts_with(const string &a, const string &b);
vector<string> split(const string &s, char separator);
string ip_to_string(uint32_t ip);
uint32_t string_to_ip(const string &ip_s);
vector<string> ancestors(const string &path);

#endif
