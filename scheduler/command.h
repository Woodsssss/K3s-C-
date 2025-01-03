#ifndef COMMAND_H
#define COMMAND_H

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <iostream>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

class Command {
public:
    using RunFunc = std::function<int(const std::vector<std::string>&)>;
    using PreRunFunc = std::function<int(const std::vector<std::string>&)>;
    using PostRunFunc = std::function<int(const std::vector<std::string>&)>;
    using ValidArgsFunc = std::function<std::vector<std::string>(const std::vector<std::string>&, const std::string&)>;

    Command(const std::string& use, const std::string& shortDesc, const std::string& longDesc)
        : use_(use), shortDesc_(shortDesc), longDesc_(longDesc) {}

    void SetPersistentPreRun(PreRunFunc func) {
        persistentPreRun_ = func;
    }

    void SetPersistentPreRunE(PreRunFunc func) {
        persistentPreRunE_ = func;
    }

    void SetPreRun(PreRunFunc func) {
        preRun_ = func;
    }

    void SetPreRunE(PreRunFunc func) {
        preRunE_ = func;
    }

    void SetRun(RunFunc func) {
        run_ = func;
    }

    void SetRunE(RunFunc func) {
        runE_ = func;
    }

    void SetPostRun(PostRunFunc func) {
        postRun_ = func;
    }

    void SetPostRunE(PostRunFunc func) {
        postRunE_ = func;
    }

    void SetPersistentPostRun(PostRunFunc func) {
        persistentPostRun_ = func;
    }

    void SetPersistentPostRunE(PostRunFunc func) {
        persistentPostRunE_ = func;
    }

    void SetValidArgsFunction(ValidArgsFunc func) {
        validArgsFunction_ = func;
    }

    int Execute(const std::vector<std::string>& args) {
        if (persistentPreRun_) {
            int result = persistentPreRun_(args);
            if (result != 0) return result;
        }

        if (preRun_) {
            int result = preRun_(args);
            if (result != 0) return result;
        }

        if (run_) {
            int result = run_(args);
            if (result != 0) return result;
        }

        if (postRun_) {
            int result = postRun_(args);
            if (result != 0) return result;
        }

        if (persistentPostRun_) {
            int result = persistentPostRun_(args);
            if (result != 0) return result;
        }

        return 0;
    }

    void PrintHelp() const {
        std::cout << "Usage: " << use_ << std::endl;
        std::cout << shortDesc_ << std::endl;
        std::cout << longDesc_ << std::endl;
    }

    po::options_description& Flags() {
        return flags_;
    }

private:
    std::string use_;
    std::string shortDesc_;
    std::string longDesc_;
    PreRunFunc persistentPreRun_;
    PreRunFunc persistentPreRunE_;
    PreRunFunc preRun_;
    PreRunFunc preRunE_;
    RunFunc run_;
    RunFunc runE_;
    PostRunFunc postRun_;
    PostRunFunc postRunE_;
    PostRunFunc persistentPostRun_;
    PostRunFunc persistentPostRunE_;
    ValidArgsFunc validArgsFunction_;
    po::options_description flags_;
};

#endif // COMMAND_H