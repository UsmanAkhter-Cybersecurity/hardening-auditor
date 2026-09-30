from dataclasses import dataclass
from typing import Any, Optional   


@dataclass 

class CheckDefinition: 

    type: str
    file: Optional[str] = None
    key: Optional[str] = None
    path: Optional[str] = None
    service: Optional[str] = None
    expected: Any = None
    message: Optional[str] = None
    command: Optional[str] = None
    package: Optional[str] = None

@dataclass

class RemediationDefinition:
 
    action: str
    value: Any = None
    file: Optional[str] = None
    


@dataclass

class Rule: 
    id: str
    title: str
    os: str
    severity : str
    check: CheckDefinition
    remediation: Optional[RemediationDefinition] = None
    description: str = ""


@dataclass

class CheckResult: 

    rule_id: str
    title: str 
    severity: str
    passed: bool
    actual_value: Any = None
    expected_value: Any = None
    error: Optional[str] = None