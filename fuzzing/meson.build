extra_sources = []
extra_cargs = []
extra_ldargs = []
fuzzing_engine = []


extra_cargs += '-g'
if fuzzer_build
  extra_cargs += '-fsanitize=fuzzer,address'
  extra_cargs += '-fsanitize-coverage=edge,indirect-calls,trace-cmp'
  extra_cargs += '-DCUSTOM_MUTATOR'
  extra_cargs += '-fprofile-instr-generate'
  extra_cargs += '-fcoverage-mapping'

  extra_ldargs += '-fsanitize=fuzzer,address'
  extra_ldargs += '-fprofile-instr-generate'
  extra_ldargs += '-fcoverage-mapping'
endif

deps = [glib_dep, libslirp_dep, platform_deps]

exes = [['fuzz-ip-header', ['slirp_fuzz_ip_header.c', 'helper.c']],
        ['fuzz-udp', ['slirp_fuzz_udp.c', 'helper.c']]]
# [fuzz-icmp, [fuzz icmp, helper.c]] pareil pour tcp
if fuzzer_build
  foreach exe : exes
    executable(
      exe[0], exe[1],
      dependencies : deps,
      c_args: extra_cargs,
      link_args: extra_ldargs,
    )
  endforeach
endif

if fuzz_reproduce
  executable(['reproducer', ['reproducer.c']], dependencies: deps, c_args: extra_cargs)
endif

/* Improve the usability of the fuzzers: */

struct Command {
    const char *build_type;
    const char *command;
    const char *fuzzing_input;
};

struct Command commands[] = {
    {"build_icmp", "build/fuzzing/slirp_fuzz_icmp", "fuzzing/IN_ICMP"},
    {"build_ip", "build/fuzzing/slirp_fuzz_ip_header", "fuzzing/IN_tftp"},
    {"build_tcp", "build/fuzzing/slirp_fuzz_tcp", "fuzzing/IN_TCP"},
    {"build_udp", "build/fuzzing/slirp_fuzz_udp", "fuzzing/IN_UDP"}
};

# Iterate over the commands array and execute the appropriate command based on build type
for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    if (build_enabled(commands[i].build_type)) {
        run_command(commands[i].command, commands[i].fuzzing_input);
    }
}
