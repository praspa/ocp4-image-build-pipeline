# ocp4-image-build-pipeline

proof of concept secure image build pipeline

https://github.com/marrober/pipelineBuildExample

## CIS Benchmark Control Checklists

```
$ ls -al ./security/benchmarks/
total 64
drwx------. 1 praspant praspant    32 Sep 30 13:35 .
drwx------. 1 praspant praspant    52 Sep 30 13:35 ..
-rw-rw-r--. 1 praspant praspant 62906 Sep 30 13:35 cis_tomcat9.json
```

## Sample Control Check (Audit/Remediation) 

```
...
      {
        "id": "8.1",
        "level": "1",
        "description": "Restrict runtime access to sensitive packages (Automated)",
        "audits": [
          {
            "applicable_checks": [
              {
                "cmd": "ls -l $JWS_HOME/conf/catalina.properties",
                "result": "0",
                "result_type": "rc"
              }
            ],
            "cmd": "grep 'package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.' $JWS_HOME/conf/catalina.properties",
            "result": "0",
            "result_type": "rc"
          }
        ],
        "remediations": [
          {
            "applicable_checks": [],
            "cmd": "sed -i 's/package.access=.*/package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat./g $JWS_HOME/conf/catalina.properties",
            "result": "0",
            "result_type": "rc"
          }
        ]
      },
...
```

## Benchmark Driver Script and Usage

Driver Script Location:

```
$ ls -al ./security/
total 12
drwx------. 1 praspant praspant    52 Sep 30 13:35 .
drwxrwxr-x. 1 praspant praspant   144 Sep 30 13:56 ..
drwx------. 1 praspant praspant    32 Sep 30 13:35 benchmarks
-rw-rw-r--. 1 praspant praspant 11972 Sep 30 13:35 run_benchmark.py
```

Driver script usage:

```
usage: run_benchmark.py [-h] [-i CONF_FILE] [-r] [-a] [-x CONTROL_REGEXP] [-s CONTROL_IGNORE]

Utility to audit and remediate applications, runtimes, and platforms.

options:
  -h, --help         show this help message and exit
  -i CONF_FILE       The benchmark configuration file.
  -r                 Perform remediation.
  -a                 Perform audit.
  -x CONTROL_REGEXP  Regular expression of what controls to audit and remediate.
  -s CONTROL_IGNORE  Comma separated list of control ids to ignore.
```

Example:

```
python run_benchmark.py -i ./benchmarks/cis_tomcat9.json \
    -a -s "5.1,6.1,6.5,7.6,9.1,9.3,10.2,10.11,10.19" | tee /security/cis_results.log
```
