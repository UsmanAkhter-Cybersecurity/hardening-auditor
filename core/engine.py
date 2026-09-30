import yaml 

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
        