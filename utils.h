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

class errno_error: public runtime_error {
    string what_message;
public:
    errno_error(const string &message, const string &file, long line);
    virtual const char* what() const noexcept;
};

void file_write(const string &path, const string &data);
string file_read_fully(const string &path);
void exec(std::initializer_list<string> cmd);
bool is_regular(const string &path);
bool is_link(const string &path);
bool starts_with(const string &a, const string &b);
string ip_to_string(uint32_t ip);
vector<string> ancestors(const string &path);
uint64_t dir_size(const string &path);

#endif
