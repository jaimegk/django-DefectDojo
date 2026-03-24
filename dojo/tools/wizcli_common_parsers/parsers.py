from dojo.models import Finding


class WizcliParsers:

    @staticmethod
    def parse_libraries(libraries, test):
        findings = []
        if libraries:
            for library in libraries:
                lib_name = library.get("name", "N/A")
                lib_version = library.get("version", "N/A")
                lib_path = library.get("path", "N/A")
                vulnerabilities = library.get("vulnerabilities", [])

                for vulnerability in vulnerabilities:
                    vuln_name = vulnerability.get("name", "N/A")
                    severity = vulnerability.get("severity", "low").lower().capitalize()
                    fixed_version = vulnerability.get("fixedVersion", "N/A")
                    source = vulnerability.get("source", "N/A")
                    description = vulnerability.get("description", "N/A")
                    score = vulnerability.get("score", "N/A")
                    exploitability_score = vulnerability.get("exploitabilityScore", "N/A")
                    has_exploit = vulnerability.get("hasExploit", False)
                    has_cisa_kev_exploit = vulnerability.get("hasCisaKevExploit", False)

                    finding_description = (
                        f"**Library Name**: {lib_name}\n"
                        f"**Library Version**: {lib_version}\n"
                        f"**Library Path**: {lib_path}\n"
                        f"**Vulnerability Name**: {vuln_name}\n"
                        f"**Fixed Version**: {fixed_version}\n"
                        f"**Source**: {source}\n"
                        f"**Description**: {description}\n"
                        f"**Score**: {score}\n"
                        f"**Exploitability Score**: {exploitability_score}\n"
                        f"**Has Exploit**: {has_exploit}\n"
                        f"**Has CISA KEV Exploit**: {has_cisa_kev_exploit}\n"
                    )

                    if fixed_version and fixed_version != "N/A":
                        mitigation = f"Upgrade to version {fixed_version}"
                    else:
                        mitigation = None
                    finding = Finding(
                        title=f"{lib_name} - {vuln_name}",
                        description=finding_description,
                        file_path=lib_path,
                        severity=severity,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=mitigation,
                        test=test,
                    )
                    findings.append(finding)
        return findings

    @staticmethod
    def parse_secrets(secrets, test):
        findings = []
        if secrets:
            for secret in secrets:
                secret_id = secret.get("id", "N/A")
                desc = secret.get("description", "N/A")
                severity = "High"
                file_name = secret.get("path", "N/A")
                line_number = secret.get("lineNumber", "N/A")
                match_content = secret.get("type", "N/A")

                description = (
                    f"**Secret ID**: {secret_id}\n"
                    f"**Description**: {desc}\n"
                    f"**File Name**: {file_name}\n"
                    f"**Line Number**: {line_number}\n"
                    f"**Match Content**: {match_content}\n"
                )

                finding = Finding(
                    title=f"Secret: {desc}",
                    description=description,
                    severity=severity,
                    file_path=file_name,
                    line=line_number,
                    static_finding=True,
                    dynamic_finding=False,
                    mitigation=None,
                    test=test,
                )
                findings.append(finding)
        return findings

    @staticmethod
    def parse_rule_matches(rule_matches, test):
        findings = []
        if rule_matches:
            for rule_match in rule_matches:
                rule = rule_match.get("rule", {})
                rule_id = rule.get("id", "N/A")
                rule_name = rule.get("name", "N/A")
                severity = rule_match.get("severity", "low").lower().capitalize()

                matches = rule_match.get("matches", [])
                if matches:
                    for match in matches:
                        resource_name = match.get("resourceName", "N/A")
                        file_name = match.get("fileName", "N/A")
                        line_number = match.get("lineNumber", "N/A")
                        match_content = match.get("matchContent", "N/A")
                        expected = match.get("expected", "N/A")
                        found = match.get("found", "N/A")
                        file_type = match.get("fileType", "N/A")

                        description = (
                            f"**Rule ID**: {rule_id}\n"
                            f"**Rule Name**: {rule_name}\n"
                            f"**Resource Name**: {resource_name}\n"
                            f"**File Name**: {file_name}\n"
                            f"**Line Number**: {line_number}\n"
                            f"**Match Content**: {match_content}\n"
                            f"**Expected**: {expected}\n"
                            f"**Found**: {found}\n"
                            f"**File Type**: {file_type}\n"
                        )

                        finding = Finding(
                            title=f"{rule_name} - {resource_name}",
                            description=description,
                            severity=severity,
                            file_path=file_name,
                            line=line_number,
                            static_finding=True,
                            dynamic_finding=False,
                            mitigation=None,
                            test=test,
                        )
                        findings.append(finding)
        return findings

    @staticmethod
    def parse_os_packages(os_packages, test):
        findings = []
        if os_packages:
            for osPackage in os_packages:
                pkg_name = osPackage.get("name", "N/A")
                pkg_version = osPackage.get("version", "N/A")
                vulnerabilities = osPackage.get("vulnerabilities", [])

                for vulnerability in vulnerabilities:
                    vuln_name = vulnerability.get("name", "N/A")
                    severity = vulnerability.get("severity", "low").lower().capitalize()
                    fixed_version = vulnerability.get("fixedVersion", "N/A")
                    source = vulnerability.get("source", "N/A")
                    description = vulnerability.get("description", "N/A")
                    score = vulnerability.get("score", "N/A")
                    exploitability_score = vulnerability.get("exploitabilityScore", "N/A")
                    has_exploit = vulnerability.get("hasExploit", False)
                    has_cisa_kev_exploit = vulnerability.get("hasCisaKevExploit", False)

                    finding_description = (
                        f"**OS Package Name**: {pkg_name}\n"
                        f"**OS Package Version**: {pkg_version}\n"
                        f"**Vulnerability Name**: {vuln_name}\n"
                        f"**Fixed Version**: {fixed_version}\n"
                        f"**Source**: {source}\n"
                        f"**Description**: {description}\n"
                        f"**Score**: {score}\n"
                        f"**Exploitability Score**: {exploitability_score}\n"
                        f"**Has Exploit**: {has_exploit}\n"
                        f"**Has CISA KEV Exploit**: {has_cisa_kev_exploit}\n"
                    )

                    if fixed_version and fixed_version != "N/A":
                        mitigation = f"Upgrade to version {fixed_version}"
                    else:
                        mitigation = None
                    finding = Finding(
                        title=f"{pkg_name} - {vuln_name}",
                        description=finding_description,
                        severity=severity,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=mitigation,
                        test=test,
                    )
                    findings.append(finding)
        return findings

    @staticmethod
    def parse_end_of_life(end_of_life_findings, test):
        findings = []
        if end_of_life_findings:
            for eol in end_of_life_findings:
                name = eol.get("name", "N/A")
                version = eol.get("version", "N/A")
                path = eol.get("path", "N/A")
                eol_date = eol.get("endOfLifeDate", "N/A")
                vulnerabilities = eol.get("vulnerabilities", [])

                for vulnerability in vulnerabilities:
                    vuln_name = vulnerability.get("name", "N/A")
                    severity_raw = vulnerability.get("severity", "low")
                    severity = severity_raw.lower().capitalize()
                    fixed_version = vulnerability.get("fixedVersion", "N/A")
                    source = vulnerability.get("source", "N/A")
                    description = vulnerability.get("description", "N/A")
                    score = vulnerability.get("score", "N/A")

                    finding_description = (
                        f"**Technology Name**: {name}\n"
                        f"**Technology Version**: {version}\n"
                        f"**Path**: {path}\n"
                        f"**End Of Life Date**: {eol_date}\n"
                        f"**Vulnerability Name**: {vuln_name}\n"
                        f"**Fixed Version**: {fixed_version}\n"
                        f"**Source**: {source}\n"
                        f"**Description**: {description}\n"
                        f"**Score**: {score}\n"
                    )

                    if fixed_version and fixed_version != "N/A":
                        mitigation = f"Upgrade to version {fixed_version}"
                    else:
                        mitigation = None
                    finding = Finding(
                        title=f"{name} - {vuln_name}",
                        description=finding_description,
                        severity=severity,
                        file_path=path,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=mitigation,
                        test=test,
                    )
                    findings.append(finding)
        return findings

    @staticmethod
    def parse_data_findings(data_findings, test):
        findings = []
        if data_findings:
            for data in data_findings:
                external_id = data.get("externalId", "N/A")
                data_classifier = data.get("dataClassifier", {})
                classifier_name = data_classifier.get("name", "N/A")
                match_count = data.get("matchCount", "N/A")
                severity_raw = data.get("severity", "low")
                severity = severity_raw.lower().capitalize()

                finding_description = (
                    f"**External ID**: `{external_id}`\n"
                    f"**Data Classifier**: {classifier_name}\n"
                    f"**Match Count**: {match_count}\n"
                )

                examples = data.get("examples", [])
                if examples:
                    finding_description += "\n**Examples:**\n"
                    for ex in examples:
                        path_str = str(ex.get("path", "N/A")).replace("`", "'")
                        val_str = str(ex.get("value", "N/A")).replace("`", "'")
                        finding_description += (
                            f"- Path: `{path_str}` | Value: `{val_str}`\n"
                        )

                finding = Finding(
                    title=f"Data Finding - {classifier_name}",
                    description=finding_description,
                    severity=severity,
                    static_finding=True,
                    dynamic_finding=False,
                    test=test,
                )
                findings.append(finding)
        return findings

    @staticmethod
    def parse_cpes(cpes, test):
        findings = []
        if cpes:
            for cpe in cpes:
                name = cpe.get("name", "N/A")
                version = cpe.get("version", "N/A")
                path = cpe.get("path", "N/A")
                vulnerabilities = cpe.get("vulnerabilities", [])

                for vulnerability in vulnerabilities:
                    vuln_name = vulnerability.get("name", "N/A")
                    severity_raw = vulnerability.get("severity", "low")
                    severity = severity_raw.lower().capitalize()
                    fixed_version = vulnerability.get("fixedVersion", "N/A")
                    source = vulnerability.get("source", "N/A")
                    description = vulnerability.get("description", "N/A")
                    score = vulnerability.get("score", "N/A")

                    finding_description = (
                        f"**CPE Name**: {name}\n"
                        f"**CPE Version**: {version}\n"
                        f"**Path**: {path}\n"
                        f"**Vulnerability Name**: {vuln_name}\n"
                        f"**Fixed Version**: {fixed_version}\n"
                        f"**Source**: {source}\n"
                        f"**Description**: {description}\n"
                        f"**Score**: {score}\n"
                    )

                    if fixed_version and fixed_version != "N/A":
                        mitigation = f"Upgrade to version {fixed_version}"
                    else:
                        mitigation = None
                    finding = Finding(
                        title=f"{name} - {vuln_name}",
                        description=finding_description,
                        severity=severity,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=mitigation,
                        test=test,
                    )
                    findings.append(finding)
        return findings

    @staticmethod
    def convert_status(wiz_status) -> dict:
        """
        Convert the Wiz Status to a dict of Finding status flags.

        - Open-> Active = True
        - Other statuses that may exist...
        """
        if (status := wiz_status) is not None:
            if status.upper() == "OPEN":
                return {"active": True}
            if status.upper() == "RESOLVED":
                return {"active": False, "is_mitigated": True}
            if status.upper() == "IGNORED":
                return {"active": False, "out_of_scope": True}
            if status.upper() == "IN_PROGRESS":
                return {"active": True}
        # Return the default status of active
        return {"active": True}
