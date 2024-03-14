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

project('fuzzing', 'c')

# Command struct definition
command_headers = configure_file(input: 'command.h.in', output: 'command.h')

# Define an array of commands
commands = [
  ['build_icmp', 'build/fuzzing/slirp_fuzz_icmp', 'fuzzing/IN_ICMP'],
  ['build_ip', 'build/fuzzing/slirp_fuzz_ip_header', 'fuzzing/IN_tftp'],
  ['build_tcp', 'build/fuzzing/slirp_fuzz_tcp', 'fuzzing/IN_TCP'],
  ['build_udp', 'build/fuzzing/slirp_fuzz_udp', 'fuzzing/IN_UDP'],
]

# Iterate over the commands array and execute the appropriate command based on build type
foreach cmd : commands
  if get_option(cmd[0]).enabled()
    executable(cmd[1], 'command.c', output: cmd[1])
    run_target(cmd[0], cmd[1], args: cmd[2])
  endif
endforeach

