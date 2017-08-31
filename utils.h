#ifndef UNPLUG_UTILS_H
#define UNPLUG_UTILS_H

#include <string>
#include <vector>
using std::string;
using std::vector;

void file_write(const string &path, const string &data);
void exec(std::initializer_list<string> cmd);
bool is_regular(const string &path);
string ip_to_string(uint32_t ip);
vector<string> ancestors(const string &path);
uint64_t dir_size(const string &path);

#endif
