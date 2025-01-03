#include <iostream>
#include <cstdlib>
#include <vector>
#include <boost/program_options.hpp>
#include "command.h"
#include "server.cpp"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    auto command = NewSchedulerCommand();

    po::variables_map vm;
    po::options_description flags = command->Flags();
    po::store(po::parse_command_line(argc, argv, flags), vm);
    po::notify(vm);

    if (vm.count("help")) {
        command->PrintHelp();
        return 0;
    }

    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
    }

    return command->Execute(args);
}