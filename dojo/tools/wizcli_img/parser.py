import json

from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers


class WizcliImgParser:

    """Wizcli Image Scan results in JSON file format."""

    def get_scan_types(self):
        return ["Wizcli Img Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli Img Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli Img report file can be imported in JSON format."

    def get_findings(self, filename, test):
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        osPackages = results.get("osPackages", None)
        if osPackages:
            findings.extend(WizcliParsers.parse_os_packages(osPackages, test))

        libraries = results.get("libraries", None)
        if libraries:
            findings.extend(WizcliParsers.parse_libraries(libraries, test))

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

        return findings
