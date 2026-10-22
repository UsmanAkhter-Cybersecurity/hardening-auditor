import yaml 
import subprocess
import os
import stat


from core.rule_schema import Rule, CheckDefinition, RemediationDefinition





def load_rules(yaml_path): 
    with open(yaml_path, 'r') as file:
        rules_data = yaml.safe_load(file)

    rules = []

    for rule_data in rules_data:
        check_data = rule_data['check']
        check = CheckDefinition(**check_data)


        remediation_data = rule_data.get('remediation')
        remediation = RemediationDefinition(**remediation_data) if remediation_data else None

        rule = Rule(
            id=rule_data['id'],
            title=rule_data['title'],
            os=rule_data['os'],
            severity=rule_data['severity'],
            check=check,
            remediation=remediation,
            description=rule_data.get('description', '')

        )
        rules.append(rule)    

    return rules



def run_check(rule):
    if rule.check.type == "command_output":
        result = subprocess.run(
            rule.check.command,
            shell=True,
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()
        error = result.stderr.strip()

        passed = rule.check.expected in output
        print("Passed:", passed, "|" " Actual: ", output, "|" " Expected: ", rule.check.expected)



    elif rule.check.type == "config_value": 
        try:
        
            with open(rule.check.file, 'r') as file:
                lines = file.readlines()
            
            found_value = None
            for line in lines:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.startswith(rule.check.key):
                    found_value = line

            


            if found_value is None:
                passed = False
                actual = "not set"

            else:
                actual = found_value.split("=")[1].strip()
                passed = (actual == rule.check.expected)

            print("Passed:", passed, "|" " Actual: ", actual, "|" " Expected: ", rule.check.expected)

        except FileNotFoundError:
            print(f"Configuration file {rule.check.file} not found.")

    


    elif rule.check.type == "package_installed":
        command = f"dpkg -s {rule.check.package}"
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()
        error = result.stderr.strip()
        print("STDOUT:", output)
        print("STDERR:", error)

        passed = result.returncode == 0 and "Install: OK Installed" in output
        print("Passed:", passed, "|" " Actual: ", output.splitlines()[1] if output else "not installed", "|" " Expected: ", rule.check.expected)
        
           

    elif rule.check.type == "file_permission":
        try:
            file_stat = os.stat(rule.check.path)
            actual_permission = stat.S_IMODE(file_stat.st_mode)
            expected_permission = int(rule.check.expected, 8) 
            
            passed = actual_permission == expected_permission
            print("Passed:", passed, "|", " Actual: ", oct(actual_permission), "|" " Expected: ", oct(expected_permission))
        

        
        
        except FileNotFoundError:
            print(f"File {rule.check.path} not found.") 
