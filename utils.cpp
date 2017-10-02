#include <cstdio>
#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#include "utils.h"

using std::runtime_error;
using std::to_string;

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

void exec(std::initializer_list<string> cmd) {
    string full_cmd;
    for (const string &s : cmd) {
        full_cmd += s;
        full_cmd += " ";
    }

    pid_t pid = fork();
    if (pid == -1)
        fail("fork failed");

    if (pid == 0) {
        fclose(stdin);

        int argc = cmd.size();
        char *ccmd[argc + 1];
        int i = 0;
        for (const string &s : cmd) {
            ccmd[i++] = strdup(s.c_str());
        }
        ccmd[argc] = NULL;

        if (false) {
            printf("%s\n", full_cmd.c_str());
        }
        execvp(ccmd[0], ccmd);
    }

    int stat;
    if (waitpid(pid, &stat, 0) != pid || stat != 0)
        throw runtime_error(full_cmd);
}

bool is_regular(const string &path) {
    struct stat s;
    if (stat(path.c_str(), &s)) {
        fail("stat " + path);
    }
    return (s.st_mode & S_IFREG) == S_IFREG;
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

vector<string> list_dir(const string &path) {
    vector<string> result;
    DIR *d = opendir(path.c_str());
    if (!d) {
        fail("listing " + path);
    }
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(d)) != NULL) {
        if (!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name))
            continue;
        result.push_back(entry->d_name);
    }
    if (errno != 0) {
        fail("listing " + path);
    }
    closedir(d);
    return result;
}

string path_join(const string &a, const string &b) {
    if (b.front() == '/')
        return b;
    return a.back() != '/'
        ? a + '/' + b
        : a + b;
}

uint64_t dir_size(const string &path) {
    uint64_t total = 0;
    for (const string &file : list_dir(path)) {
        string child = path_join(path, file);
        struct stat s;
        if (stat(child.c_str(), &s)) {
            fail("stat " + child);
        }
        if ((s.st_mode & S_IFREG) == S_IFREG) {
            total += s.st_size;
        }
        else if ((s.st_mode & S_IFDIR) == S_IFDIR) {
            total += dir_size(child);
        }
    }
    return total;
}
