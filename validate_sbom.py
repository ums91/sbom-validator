import os
import json

SBOM_FOLDER = "SBOMs to be checked"
README_FILE = "README.md"
EXPECTED_SUPPLIER_NAME = "test supplier"
REQUIRED_ROOT_FIELDS = ["bomFormat", "specVersion", "metadata", "components", "dependencies"]
REQUIRED_COMPONENT_FIELDS = ["name", "type", "version", "author", "licenses", "bom-ref"]
REQUIRED_ID_FIELDS = ["purl", "cpe", "swid"]

def validate_sbom(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except Exception as e:
            return False, [f"❌ Invalid JSON: {e}"]

    missing = []

    for field in REQUIRED_ROOT_FIELDS:
        if field not in data:
            missing.append(f"🔴 Missing root field: `{field}`")

    if data.get("bomFormat") != "CycloneDX":
        missing.append(f"🔴 Invalid value for `bomFormat`: `{data.get('bomFormat')}` (Expected: `CycloneDX`)")

    if data.get("specVersion") != "1.6.1":
        missing.append(f"🔴 Invalid value for `specVersion`: `{data.get('specVersion')}` (Expected: `1.6.1`)")

    if not isinstance(data.get("metadata", {}).get("timestamp"), str):
        missing.append("🔴 Missing or invalid `metadata.timestamp` (Expected: string)")

    components = data.get("components", [])
    for idx, comp in enumerate(components):
        prefix = f"🧩 Component[{idx}]"

        if comp.get("supplier", {}).get("name") != EXPECTED_SUPPLIER_NAME:
            missing.append(f"{prefix}: Missing or incorrect `supplier.name` (Expected: `{EXPECTED_SUPPLIER_NAME}`)")

        for field in REQUIRED_COMPONENT_FIELDS:
            if field not in comp:
                missing.append(f"{prefix}: Missing field `{field}`")

        if "licenses" in comp:
            for lic in comp["licenses"]:
                if not isinstance(lic, dict) or "license" not in lic or "id" not in lic["license"]:
                    missing.append(f"{prefix}: Invalid SPDX license format")

        if not any(id_key in comp for id_key in REQUIRED_ID_FIELDS):
            missing.append(f"{prefix}: Missing one of identifier fields: `purl`, `cpe`, or `swid`")

        found = any(
            prop.get("name") == "previous_version"
            for prop in comp.get("properties", [])
            if isinstance(prop, dict)
        )
        if not found:
            missing.append(f"{prefix}: Missing property `previous_version` in `properties`")

    return (len(missing) == 0), missing

def append_result(sbom_name, is_valid, issues):
    new_section = [f"## ✅ Result for `{sbom_name}`\n"]
    if is_valid:
        new_section.append("✅ All required parameters are present and valid.\n")
    else:
        new_section.append("❌ Validation failed. Missing or invalid parameters:\n")
        for issue in issues:
            new_section.append(f"- {issue}\n")

    # Read existing content
    existing_lines = []
    if os.path.exists(README_FILE):
        with open(README_FILE, 'r', encoding='utf-8') as f:
            existing_lines = f.readlines()

    # Remove old section for this SBOM
    updated_lines = []
    skip = False
    for line in existing_lines:
        if line.startswith(f"## ✅ Result for `{sbom_name}`"):
            skip = True
            continue
        if skip and line.startswith("## ✅ Result for `"):
            skip = False  # End of this SBOM section
        if not skip:
            updated_lines.append(line)

    # Append new result
    updated_lines.append("\n" + "".join(new_section))

    # Write back to README
    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.writelines(updated_lines)

def main():
    if not os.path.exists(SBOM_FOLDER):
        os.makedirs(SBOM_FOLDER)

    for sbom in os.listdir(SBOM_FOLDER):
        if not sbom.endswith(".json"):
            continue

        filepath = os.path.join(SBOM_FOLDER, sbom)
        is_valid, issues = validate_sbom(filepath)
        append_result(sbom, is_valid, issues)

if __name__ == "__main__":
    main()
