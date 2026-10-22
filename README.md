
I approve the selection of MAGIC and AFFECTATION for the first SAST qualification run.

Proceed with the preparation phase only.

1. Persist the nine validated CXone-to-Azure DevOps repository mappings in the local mapping configuration, without storing credentials.
2. Clone the required repositories under workspace/MAGIC/ and workspace/AFFECTATION/, using read-only Azure DevOps credentials and disabling push URLs for local clones.
3. Record the current branch, HEAD commit SHA, and working-tree status for each clone.
4. Retrieve the exact scan commit SHA from CXone scan metadata, scan details or approved CI/CD metadata when available. Never treat the current branch HEAD as the scan commit.
5. If the scan SHA cannot be established, flag SCAN_BASELINE_UNKNOWN and do not conclude NOT_EXPLOITABLE based solely on the current code.
6. Identify dependencies and interactions between frontend, backend, APIs and shared libraries.
7. Create application context files outside the cloned repositories.
8. Prepare a pilot batch of five Critical findings from MAGIC/EASI and two from AFFECTATION, without starting qualification.

Strict restrictions: Never modify application source code, create commits, push, create branches, apply patches, change CXone statuses or post comments. Do not execute .ps1 scripts or change PowerShell execution policy.

Produce a French preparation report with repository paths, Git baselines, scan SHA availability and pilot finding IDs. Wait for my approval before analyzing the findings.
