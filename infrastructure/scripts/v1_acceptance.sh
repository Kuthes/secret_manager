#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "      AEGISVAULT v1.0 PRODUCTION ACCEPTANCE RUNNER"
echo "============================================================"

FAILED_GATES=0

run_gate() {
    local gate_name="$1"
    local command="$2"
    echo ""
    echo "[*] RUNNING GATE: ${gate_name}..."
    if eval "${command}"; then
        echo "✅ GATE PASSED: ${gate_name}"
    else
        echo "❌ GATE FAILED: ${gate_name}"
        FAILED_GATES=$((FAILED_GATES + 1))
    fi
}

# 1. Backend Security & Functional Regression Suite
run_gate "Backend Security & Functional Suite" \
  "PYTHONPATH=.:sdk/python /home/saurabh/.local/bin/uv run --with-requirements apps/api/requirements.txt pytest tests/ -v"

# 2. Cryptographic Adversarial & Nonce Safety Gate
run_gate "Cryptographic Adversarial & Nonce Safety" \
  "PYTHONPATH=.:sdk/python /home/saurabh/.local/bin/uv run --with-requirements apps/api/requirements.txt pytest tests/security/test_crypto_adversarial.py -v"

# 3. Machine Identity (Universal, K8s, OIDC) Gate
run_gate "Machine Identity Authentication" \
  "PYTHONPATH=.:sdk/python /home/saurabh/.local/bin/uv run --with-requirements apps/api/requirements.txt pytest tests/security/test_machine_identity.py -v"

# 4. Disaster Recovery Simulation Gate
run_gate "Automated Disaster Recovery Simulation" \
  "PYTHONPATH=.:sdk/python /home/saurabh/.local/bin/uv run --with-requirements apps/api/requirements.txt pytest tests/disaster_recovery/test_disaster_recovery_simulation.py -v"

# 5. Frontend & UI Component Gate
run_gate "Frontend Unit & Component Tests" \
  "node --test tests/*.mjs"

echo ""
echo "============================================================"
if [ ${FAILED_GATES} -eq 0 ]; then
    echo "🎉 ALL ACCEPTANCE GATES PASSED! CLASSIFICATION: PRODUCTION READY"
    echo "============================================================"
    exit 0
else
    echo "⚠️  ${FAILED_GATES} GATE(S) FAILED. CLASSIFICATION: BLOCKED"
    echo "============================================================"
    exit 1
fi
