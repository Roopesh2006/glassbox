"""Built-in pre-tuned policy profiles for top official MCP servers (2026).

Usage:
    glassbox wrap --policy balanced --profile github -- npx -y @modelcontextprotocol/server-github
    glassbox wrap --policy strict --profile all -- <any-mcp-server>
"""

from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, list[str]]] = {
    "github": {
        "private_tool_patterns": [r"(?i)^(get_file_contents|search_code|get_secret|list_repository_secrets)$"],
        "untrusted_tool_patterns": [r"(?i)^(get_issue|list_issues|get_issue_comments|get_pull_request|list_pull_requests|get_pull_request_comments|search_issues)$"],
        "egress_tool_patterns": [r"(?i)^(add_issue_comment|create_issue|create_pull_request|push_files|create_or_update_file|fork_repository)$"],
        "destructive_tool_patterns": [r"(?i)^(delete_branch|delete_file|delete_repository|merge_pull_request)$"],
    },
    "postgres": {
        "private_tool_patterns": [r"(?i)^(query|sql_query|read_query|describe_table|list_tables)$"],
        "untrusted_tool_patterns": [],
        "egress_tool_patterns": [r"(?i)^(export_csv|copy_to_s3|webhook_notify)$"],
        "destructive_tool_patterns": [r"(?i)^(drop_table|truncate_table|delete_rows|write_query|execute_ddl)$"],
    },
    "filesystem": {
        "private_tool_patterns": [r"(?i)^(read_file|read_multiple_files|search_files|get_file_info)$"],
        "untrusted_tool_patterns": [],
        "egress_tool_patterns": [],
        "destructive_tool_patterns": [r"(?i)^(delete_file|remove_directory|move_file)$"],
    },
    "slack": {
        "private_tool_patterns": [r"(?i)^(slack_get_channel_history|slack_get_thread_replies|slack_list_users)$"],
        "untrusted_tool_patterns": [r"(?i)^(slack_get_channel_history|slack_get_thread_replies|slack_search_messages)$"],
        "egress_tool_patterns": [r"(?i)^(slack_post_message|slack_reply_to_thread|slack_upload_file)$"],
        "destructive_tool_patterns": [r"(?i)^(slack_delete_message|slack_archive_channel)$"],
    },
    "playwright": {
        "private_tool_patterns": [r"(?i)^(browser_cookies|browser_local_storage|browser_snapshot)$"],
        "untrusted_tool_patterns": [r"(?i)^(browser_navigate|browser_snapshot|browser_get_text|browser_evaluate)$"],
        "egress_tool_patterns": [r"(?i)^(browser_navigate|browser_click|browser_fill|browser_type|browser_submit)$"],
        "destructive_tool_patterns": [],
    },
    "gmail": {
        "private_tool_patterns": [r"(?i)^(get_message|list_messages|search_messages|read_thread)$"],
        "untrusted_tool_patterns": [r"(?i)^(get_message|list_messages|search_messages|read_thread)$"],
        "egress_tool_patterns": [r"(?i)^(send_message|reply_message|forward_message|create_draft)$"],
        "destructive_tool_patterns": [r"(?i)^(delete_message|trash_thread|batch_delete)$"],
    },
    "linear": {
        "private_tool_patterns": [r"(?i)^(list_issues|get_issue|list_projects)$"],
        "untrusted_tool_patterns": [r"(?i)^(get_issue|list_comments|search_issues)$"],
        "egress_tool_patterns": [r"(?i)^(create_comment|create_issue|update_issue)$"],
        "destructive_tool_patterns": [r"(?i)^(delete_issue|archive_project)$"],
    },
    "notion": {
        "private_tool_patterns": [r"(?i)^(get_page|search_pages|query_database)$"],
        "untrusted_tool_patterns": [r"(?i)^(get_page|get_comments|search_pages)$"],
        "egress_tool_patterns": [r"(?i)^(append_block_children|create_page|create_comment)$"],
        "destructive_tool_patterns": [r"(?i)^(delete_block|archive_page)$"],
    },
    "fetch": {
        "private_tool_patterns": [],
        "untrusted_tool_patterns": [r"(?i)^(fetch|fetch_url|web_search|scrape_url|crawl)$"],
        "egress_tool_patterns": [r"(?i)^(fetch|http_post|http_put|http_request)$"],
        "destructive_tool_patterns": [],
    },
    "aws": {
        "private_tool_patterns": [r"(?i)^(get_secret_value|s3_get_object|describe_instances|get_parameter)$"],
        "untrusted_tool_patterns": [r"(?i)^(s3_get_object|sqs_receive_message)$"],
        "egress_tool_patterns": [r"(?i)^(s3_put_object|sns_publish|ses_send_email|lambda_invoke)$"],
        "destructive_tool_patterns": [r"(?i)^(s3_delete_object|ec2_terminate_instances|rds_delete_db_instance|iam_delete_user)$"],
    },
    "kubernetes": {
        "private_tool_patterns": [r"(?i)^(get_secrets|get_configmaps|get_pod_logs|describe_pod)$"],
        "untrusted_tool_patterns": [r"(?i)^(get_pod_logs|get_events)$"],
        "egress_tool_patterns": [r"(?i)^(exec_pod|apply_manifest|patch_resource)$"],
        "destructive_tool_patterns": [r"(?i)^(delete_pod|delete_namespace|delete_deployment|drain_node)$"],
    },
    "stripe": {
        "private_tool_patterns": [r"(?i)^(list_customers|retrieve_customer|list_charges|get_balance)$"],
        "untrusted_tool_patterns": [r"(?i)^(list_disputes|retrieve_event)$"],
        "egress_tool_patterns": [r"(?i)^(create_payment_link|create_invoice|send_invoice)$"],
        "destructive_tool_patterns": [r"(?i)^(create_refund|cancel_subscription|delete_customer)$"],
    },
}


def list_profile_names() -> list[str]:
    return sorted(PROFILES.keys())


def merge_profile_into_policy(policy: Any, profile_spec: str) -> None:
    """Merge one or more comma-separated profile names (or 'all') into a PolicyConfig."""
    if not profile_spec:
        return
    names = [p.strip().lower() for p in profile_spec.split(",") if p.strip()]
    if "all" in names:
        selected = list(PROFILES.keys())
    else:
        unknown = [n for n in names if n not in PROFILES]
        if unknown:
            raise ValueError(
                f"Unknown profile(s): {', '.join(unknown)}. Available: all, {', '.join(list_profile_names())}"
            )
        selected = names

    for name in selected:
        prof = PROFILES[name]
        for field_name, patterns in prof.items():
            existing: list[str] = getattr(policy, field_name)
            for pat in patterns:
                if pat not in existing:
                    existing.append(pat)
    policy.name = f"{policy.name}+{'+'.join(selected) if 'all' not in names else 'all'}"
