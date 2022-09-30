# ocp4-image-build-pipeline-poc

proof of concept secure image build pipeline

https://github.com/marrober/pipelineBuildExample

## Benchmark Driver Usage

usage: run_benchmark.py [-h] [-i CONF_FILE] [-r] [-a] [-x CONTROL_REGEXP] [-s CONTROL_IGNORE]

Utility to audit and remediate applications, runtimes, and platforms.

options:
  -h, --help         show this help message and exit
  -i CONF_FILE       The benchmark configuration file.
  -r                 Perform remediation.
  -a                 Perform audit.
  -x CONTROL_REGEXP  Regular expression of what controls to audit and remediate.
  -s CONTROL_IGNORE  Comma separated list of control ids to ignore.

Example:

python run_benchmark.py -i ./benchmarks/cis_tomcat9.json \
    -a -s "5.1,6.1,6.5,7.6,9.1,9.3,10.2,10.11,10.19" | tee /security/cis_results.log
