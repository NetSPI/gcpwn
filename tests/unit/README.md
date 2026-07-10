# Unit Test Layout

This unit suite is organized by module area and only covers deterministic, offline functionality.

- `core/`: core utility behavior (`module_helpers`, `action_recording`)
- `everything/`: IAM policy mutation helpers (`exploit_gcp_setiampolicy`, `iam_policy_bindings`)
- `opengraph/`: OpenGraph helper normalization and example input -> graph output tests