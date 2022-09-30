# ocp4-image-build-pipeline-poc Design



## Processing steps

* execute pipeline with ubi8 base 
* pull into test hub quay quarentine
* acs scan on image in hub quarentine
* pull image to pipeline cache from hub
* run cis scan(s)
* remediate cis
* push to test hub quay approved namespace
* mirror to prod hub approved namespace


# Appendix


