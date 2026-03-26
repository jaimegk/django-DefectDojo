import json

from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers


class WizcliDirParser:

    """Wizcli Dir Scan results in JSON file format."""

    def get_scan_types(self):
        return ["Wizcli Dir Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli Dir Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli Dir Scan results in JSON file format."

    def get_findings(self, filename, test):
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        libraries = results.get("libraries", None)
        if libraries:
            findings.extend(WizcliParsers.parse_libraries(libraries, test))

        os_packages = results.get("osPackages", None)
        if os_packages:
            findings.extend(WizcliParsers.parse_os_packages(os_packages, test))

        secrets = results.get("secrets", None)
        if secrets:
            findings.extend(WizcliParsers.parse_secrets(secrets, test))

        end_of_life = results.get("endOfLifeTechnologies", None)
        if end_of_life:
            findings.extend(WizcliParsers.parse_end_of_life(end_of_life, test))

        data_findings = results.get("dataFindings", None)
        if data_findings:
            findings.extend(WizcliParsers.parse_data_findings(data_findings, test))

        cpes = results.get("cpes", None)
        if cpes:
            findings.extend(WizcliParsers.parse_cpes(cpes, test))

        supply_chain = results.get("softwareSupplyChain", None)
        if supply_chain:
            findings.extend(WizcliParsers.parse_software_supply_chain(supply_chain, test))

        return findings
