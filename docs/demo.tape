# pdp-mask demo tape for VHS (https://github.com/charmbracelet/vhs)
# 
# To produce a demo GIF/MP4:
#   $ go install github.com/charmbracelet/vhs@latest
#   $ vhs docs/demo.tape
#
# This script records a full scan -> plan -> apply -> verify
# round-trip on the testdata/customers_pii.csv fixture.

Output docs/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1200
Set Height 720
Set Padding 20
Set Theme "Catppuccin Mocha"

# Title
Type "# pdp-mask: deterministic PII masking for CSV"
Sleep 1s
Enter
Sleep 500ms

# Show test data sample
Type "head -3 testdata/customers_pii.csv"
Sleep 500ms
Enter
Sleep 2s

# Scan
Type "go run ./cmd/pdp-mask scan testdata/customers_pii.csv --json /tmp/plan.json"
Sleep 500ms
Enter
Sleep 4s

# Plan
Type "go run ./cmd/pdp-mask plan /tmp/plan.json --out /tmp/mask.yml"
Sleep 500ms
Enter
Sleep 3s

# Show plan
Type "cat /tmp/mask.yml"
Sleep 500ms
Enter
Sleep 2s

# Apply with salt
Type "PDP_MASK_SALT=$(openssl rand -hex 32) go run ./cmd/pdp-mask apply testdata/customers_pii.csv --config /tmp/mask.yml --out /tmp/safe.csv"
Sleep 500ms
Enter
Sleep 5s

# Show masked output
Type "head -3 /tmp/safe.csv"
Sleep 500ms
Enter
Sleep 3s

# Verify
Type "go run ./cmd/pdp-mask verify testdata/customers_pii.csv --config /tmp/mask.yml --out /tmp/safe.csv"
Sleep 500ms
Enter
Sleep 3s

# Final
Type "# PII masked. Original values cannot be recovered without the salt."
Sleep 2s
