# SBOM Validation Results

This file will be automatically updated by the CI pipeline.
Each SBOM will be validated for mandatory fields and the result will be appended below.

## ✅ Result for `valid_sbom.json`
✅ All required parameters are present and valid.

## ✅ Result for `test.json`
✅ All required parameters are present and valid.

## ✅ Result for `invalid_sbom.json`
❌ Validation failed. Missing or invalid parameters:
- 🔴 Missing root field: `dependencies`
- 🔴 Missing or invalid `metadata.timestamp` (Expected: string)
- 🧩 Component[0]: Missing or incorrect `supplier.name` (Expected: `test supplier`)
- 🧩 Component[0]: Missing field `version`
- 🧩 Component[0]: Missing field `author`
- 🧩 Component[0]: Missing field `licenses`
- 🧩 Component[0]: Missing field `bom-ref`
- 🧩 Component[0]: Missing one of identifier fields: `purl`, `cpe`, or `swid`
- 🧩 Component[0]: Missing property `previous_version` in `properties`

## ✅ Result for `partial_sbom.json`
❌ Validation failed. Missing or invalid parameters:
- 🧩 Component[0]: Missing or incorrect `supplier.name` (Expected: `test supplier`)
- 🧩 Component[0]: Missing field `author`
- 🧩 Component[0]: Missing property `previous_version` in `properties`
