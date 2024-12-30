// agent.h
#ifndef AGENT_H
#define AGENT_H

#include <boost/program_options.hpp>
//封装的curl库函数
#include "curl.h"

// 声明函数
void new_agent_command(boost::program_options::variables_map& vm);

#endif  // AGENT_H
