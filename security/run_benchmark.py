import os
import re
import json
import argparse
import sys
import subprocess

parser = argparse.ArgumentParser(description='Utility to audit and remediate applications, runtimes, and platforms.')
parser.add_argument('-i', action='store', dest='conf_file', help='The benchmark configuration file.')
parser.add_argument('-r', action='store_true', dest='do_remediate', help='Perform remediation.')
parser.add_argument('-a', action='store_true', dest='do_audit', help='Perform audit.')
parser.add_argument('-x', action='store', dest='control_regexp', help='Regular expression of what controls to audit and remediate.')
parser.add_argument('-s', action='store', dest='control_ignore', help='Comma separated list of control ids to ignore.')
# todo comma separated list of checks

results = parser.parse_args()
conf_file = results.conf_file
do_remediate = results.do_remediate
do_audit = results.do_audit
control_regexp = results.control_regexp
control_ignore = str(results.control_ignore)
ignore_list = []

if control_regexp is None:
    control_regexp = ""

if control_ignore != "":
    ignore_list = control_ignore.split(",")
    

benchmark = {}

audit_report_passed = []
audit_report_failed = []
audit_report_na = []

remediate_report_passed = []
remediate_report_failed = []

# Some Status Constants
STATUS_PASS = "Pass"
STATUS_FAIL = "Fail"
STATUS_NA = "Not Applicable"

RESULT_TYPE_RC = "rc"
RESULT_TYPE_STDOUT = "stdout"

RESULT_NONZERO = "!0"

SCRIPTS_DIR="./scripts"

def validateInput():
    if conf_file == "":
        print("error: please specify -i <benchmark file>. Good-bye!")
        sys.exit()

    if not os.path.isfile(conf_file):
        print("error: provided benchmark configuration file does not exist. Good-bye!")
        sys.exit()

    if not do_remediate and not do_audit:
        print("error: please specify -a (audit) and/or -r (remediate) arguments and try again. Good-bye!")
        sys.exit()

def loadBenchmark():
    f = open(conf_file,'r')
    global benchmark 
    benchmark = json.load(f)
    f.close()

def dumpBenchmark():
    print(json.dumps(benchmark, indent = 4))

def executeBenchmark():

    global audit_report_passed
    global audit_report_failed
    global audit_report_na

    print("===================================================================================")
    print("= Benchmark Type: " + benchmark.get('benchmark').get('type'))
    print("= Benchmark Source: " + benchmark.get('benchmark').get('upstream_source'))
    print("===================================================================================")

    if do_audit:
        print
        print("INFO: System audit enabled.")
        print

    if do_remediate:
        print
        print("INFO: System remediate enabled.")
        print

    for control in benchmark.get('benchmark').get('controls'):

        # Skip controls that don't match our pattern
        if control_regexp != "" and not re.match("^" + control_regexp, control.get('id')):
            print("Skipping control: " + control.get('id'))
            continue

        # Skip controls in ignore list
        if len(ignore_list) != 0:
            if control.get('id') in ignore_list:
                print("Skipping control: " + control.get('id') + " in ignore list.")
                continue


        print
        print("===================================================================================")
        print("= Control ID: " +  control.get('id'))
        print("= Control  Level: " +  control.get('level'))
        print("= Description: " +  control.get('description'))
        print("===================================================================================")
        print

        ## Audit
        if do_audit:

            print("Performing Audit ...")

            # Did we even make it past checks to see if applicable?
            audit_check_executed = False

            # Control Audit Status
            # Continue to run audit checks even if one fails
            audit_passed = True

            audit_count = 0

            for audit in control.get('audits'):

                audit_count += 1

                audit_applicable = True

                # Test if audit is applicable to environment
                # All applicable checks must pass for audit to be applicable
                for applicable_check in audit.get('applicable_checks'):

                    print("Applicability Check CMD: " + applicable_check.get('cmd'))

                    p = subprocess.Popen(applicable_check.get('cmd'), stdout=subprocess.PIPE, shell=True, encoding='utf8')
                    (output,error) = p.communicate()
                    p_status = p.wait()

                    # Guessing this output has newlines. Clean up for comparisons.
                    output = output.rstrip(' \t\n\r')
                    
                    # strip trailing whitespace
                    #output = output.rstrip()

                    print("Applicability Check RC: " + str(p_status))
                    print("Applicability Check Output:<" + output + ">")
                    print("Applicability Check expected Result:<" + applicable_check.get('result') + ">")

                    # Check results for return code or stdout
                    if applicable_check.get('result_type') == RESULT_TYPE_RC:
                        if (applicable_check.get('result') == RESULT_NONZERO and p_status == 0) or (applicable_check.get('result') != RESULT_NONZERO and str(p_status) != applicable_check.get('result')):
                            print("Warning: Applicability Check Failed for RC.")
                            audit_applicable = False
                            break
                    elif applicable_check.get('result_type') == RESULT_TYPE_STDOUT:
                        if (applicable_check.get('result') == RESULT_NONZERO and output == "0") or (applicable_check.get('result') != RESULT_NONZERO and output != applicable_check.get('result')):
                            print("Warning: Applicability Check Failed for STDOUT.")
                            audit_applicable = False
                            break
                    else:
                        print("Error: Unknown audit applicability check result type: " + applicable_check.get('result_type') + " for control id: " + control.get('id'))
                        audit_applicable = False
                        break

                # Go to the next audit, but don't fail the control audit check since it's not applicable
                if not audit_applicable:
                    print("Audit Applicability Check Failed. Audit: " + str(audit_count) + " Control: " + control.get('id') + " is not applicable to this environment.")
                    continue

                # made it to an actual audit check
                audit_check_executed = True

                # Audit is Applicable
                print("Audit cmd: " + audit.get('cmd'))

                p = subprocess.Popen(audit.get('cmd'),stdout=subprocess.PIPE,shell=True,encoding='utf8')
                (output,error) = p.communicate()
                p_status = p.wait()

                output = output.rstrip(' \t\n\r')

                print("Audit Check RC: " + str(p_status))
                print("Audit Check Output:<" + output + ">")
                print("Audit Check expected Result:<" + audit.get('result') + ">")

                # Check results for return code or stdout
                # Don't break here, continue to run all audits for the control
                if audit.get('result_type') == RESULT_TYPE_RC:
                    if (audit.get('result') == RESULT_NONZERO and p_status == 0) or (audit.get('result') != RESULT_NONZERO and str(p_status) != audit.get('result')):
                        print("Warning: Audit Check Failed for RC.")
                        audit_passed = False
                elif audit.get('result_type') == RESULT_TYPE_STDOUT:
                    if (audit.get('result') == RESULT_NONZERO and output == "0") or (audit.get('result') != RESULT_NONZERO and output != audit.get('result')):
                        print("Warning: Audit Check Failed for STDOUT.")
                        audit_passed = False
                else:
                    print("Error: Unknown audit result type: " + audit.get('result_type') + " for control id: " + control.get('id'))
                    audit_passed = False

        if not audit_check_executed:
            print("Control: " + control.get('id') + " - Audit Not Applicable")        
            audit_report_na.append(control.get('id'))
        elif not audit_passed:
            print("Control: " + control.get('id') + " - Audit FAIL")
            audit_report_failed.append(control.get('id'))
        else:
            print("Control: " + control.get('id') + " - Audit PASS")
            audit_report_passed.append(control.get('id'))

        ## Remediate
        # only remediate if the cmd line switch is on
        if do_remediate:

            print("Performing Remediation ...")

            remediate_passed = True

            # Only remediate if the audit check failed
            if audit_passed == False:

                for remediation in control.get('remediations'):

                    # Audit is Applicable
                    print("Remdiation cmd: " + remediation.get('cmd'))

                    p = subprocess.Popen(remediation.get('cmd'),stdout=subprocess.PIPE,shell=True,encoding='utf8')
                    (output,error) = p.communicate()
                    p_status = p.wait()

                    output = output.rstrip(' \t\n\r')

                    print("Remediation Check RC: " + str(p_status))
                    print("Remediation Check Output:<" + output + ">")
                    print("Remediation Check expected Result:<" + remediation.get('result') + ">")

                    if p_status != 0:
                        print("Warning: Remediation Failed.")
                        remediate_passed = False


                if remediate_passed == True:    
                    print("Control: " + control.get('id') + " - REMEDIATE SUCCESS")
                    remediate_report_passed.append(control.get('id'))
                else:
                    print("Control: " + control.get('id') + " - REMEDIATE FAIL")
                    remediate_report_failed.append(control.get('id'))

def createReport():

    if do_audit:
        print
        print("===================================================================================")
        print("= Audit Report")
        print("===================================================================================")

        print("Controls Not Applicable: ",len(audit_report_na))
        for control_id in audit_report_na:
            print(control_id)

        print
        
        print("Controls Passed: ",len(audit_report_passed))
        for control_id in audit_report_passed:
            print(control_id)

        print

        print("Controls Failed: ",len(audit_report_failed))
	    
        for control_id in audit_report_failed:
            print(control_id)

        print

    if do_remediate:
        print
        print("===================================================================================")
        print("= Remediation Report")
        print("===================================================================================")

        print("Controls Remediated Success: ",len(remediate_report_passed))
        for control_id in remediate_report_passed:
            print(control_id)

        print

        print("Controls Remediated Failed: ",len(remediate_report_failed))
	    
        for control_id in remediate_report_failed:
            print(control_id)

        print

def evalResults():
    if len(audit_report_failed) > 0:
        sys.exit(254)

## Main ##
validateInput()
loadBenchmark()
#dumpBenchmark()
executeBenchmark()
createReport()
evalResults()



