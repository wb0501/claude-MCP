#!/bin/bash

set -u

TASKS=(
"claude-code__feature_commit_tracking"
"claude-code__label_color_standardization"

"easyr1__advanced_branch_strategy"
"easyr1__config_parameter_audit"
"easyr1__performance_regression_investigation"
"easyr1__qwen3_issue_management"

"harmony__release_management_workflow"

"mcpmark-cicd__linting_ci_workflow"

"missing-semester__assign_contributor_labels"
"missing-semester__find_legacy_name"
)

for task in "${TASKS[@]}"
do
    echo "============================================================"
    echo "Running: $task"
    echo "============================================================"

    ./run_mcpmark_github_claude_v4.py \
        --task "$task" \
        --limit 1 \
        --sudo-dumpcap

    ret=$?

    if [ $ret -ne 0 ]; then
        echo "[FAILED COMMAND] $task"
        echo "Continue to next task..."
    else
        echo "[FINISHED] $task"
    fi

    echo
    sleep 10
done

echo "All retry tasks completed."
