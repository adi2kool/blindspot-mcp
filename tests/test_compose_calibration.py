"""Calibration corpus for the trifecta classifier.

A labeled set of real MCP server tools (filesystem, git/github, slack, gmail, web,
cloud/data) plus benign traps, scored against the classifier. This locks in the
accuracy reached after the adversarial calibration pass: the classifier is a
keyword/regex heuristic, so this corpus is the regression guard that keeps false
positives and false negatives from creeping back as the taxonomy evolves.

Leg labels reflect the trifecta framing: reading messages/issues pulls
attacker-influenceable content (untrusted_content); reading files/repos/db is
private_data; publishing to a shared place or sending outward is exfil. Issue/comment
reads are labeled untrusted_content only (their content is third-party; whether the
tracker is private depends on repo visibility the classifier cannot see).
"""

from __future__ import annotations

from airlock.compose import ServerSurface, ToolInfo, classify_server

P, U, E = "private_data", "untrusted_content", "exfil"

# (tool name, description, expected legs)
CORPUS: list[tuple[str, str, list[str]]] = [
    # filesystem / local stores (private_data; local writes are NOT exfil)
    ("read_file", "Read the complete contents of a file", [P]),
    ("read_multiple_files", "Read multiple files at once", [P]),
    ("list_directory", "List files in a directory", [P]),
    ("search_files", "Recursively search for files matching a pattern", [P]),
    ("get_file_info", "Get metadata about a file", [P]),
    ("write_file", "Write content to a local file", []),
    ("create_directory", "Create a local directory", []),
    ("read_query", "Execute a SELECT query on the SQLite database", [P]),
    ("list_tables", "List tables in the database", [P]),
    ("read_graph", "Read the entire knowledge graph", [P]),
    ("search_nodes", "Search nodes in the knowledge graph", [P]),
    ("create_entities", "Create entities in the knowledge graph", []),
    ("search", "Full-text search over the Obsidian vault", [P]),
    ("import_csv", "Load a CSV file from disk", [P]),
    # version control (private repo read; publish is exfil)
    ("git_show", "Show the contents of a commit", [P]),
    ("git_diff", "Show changes between commits", [P]),
    ("get_file_contents", "Get the contents of a file in a GitHub repo", [P]),
    ("search_code", "Search code across repositories", [P]),
    ("create_pull_request", "Open a pull request", [E]),
    ("merge_pull_request", "Merge a pull request", []),
    # issue/comment reads carry attacker content (untrusted); writes publish (exfil)
    ("list_issues", "List issues in a repository", [U]),
    ("get_issue", "Get a GitHub issue and its body", [U]),
    ("get_issue_details", "Get a Sentry issue with stacktrace", [U]),
    ("update_issue", "Change a Sentry issue status", []),
    ("create_issue", "Create a new issue with a title and body", [E]),
    ("add_issue_comment", "Add a comment to an issue", [E]),
    ("update_gist", "Update a public gist", [E]),
    # comms (message reads are dual; sends are exfil)
    ("slack_post_message", "Post a message to a Slack channel", [E]),
    ("slack_get_channel_history", "Get recent messages from a channel", [P, U]),
    ("slack_get_users", "Get the list of Slack workspace users", [P]),
    ("send_email", "Send an email to a recipient", [E]),
    ("read_email", "Read the contents of an email", [P, U]),
    ("search_emails", "Search the user's mailbox", [P, U]),
    ("read_messages", "Read messages from a Discord channel", [P, U]),
    ("list_channels", "List channels in a Discord server", []),
    ("get_messages", "Get message history from a Telegram chat", [P, U]),
    # web (arbitrary-URL fetch is dual; search is ingest only)
    ("fetch", "Fetches a URL from the internet and returns markdown", [U, E]),
    ("brave_web_search", "Perform a web search with Brave", [U]),
    ("firecrawl_scrape", "Scrape content from a web page", [U, E]),
    ("firecrawl_extract", "Extract structured data from web pages", [U, E]),
    ("browser_navigate", "Navigate the browser to a URL", [U, E]),
    ("http_request", "Make an arbitrary HTTP request to a URL", [U, E]),
    ("post_webhook", "Send an HTTP POST to a webhook URL", [E]),
    # cloud / data (reads private; writes exfil)
    ("gdrive_read_file", "Read the contents of a Google Drive file", [P]),
    ("gdrive_search", "Search files in the user's Google Drive", [P]),
    ("gdrive_create_file", "Create a new file in Google Drive", [E]),
    ("bigquery_query", "Run a query against BigQuery", [P]),
    ("read_values", "Read cell values from a Google Sheet", [P]),
    ("update_values", "Write values to a Google Sheet", [E]),
    ("get_object", "Download an object from an S3 bucket", [P]),
    ("put_object", "Upload an object to an S3 bucket", [E]),
    ("get_item", "Get an item from a DynamoDB table", [P]),
    ("put_item", "Write an item to a DynamoDB table", [E]),
    ("create_record", "Create a record in Airtable", [E]),
    # benign traps (no leg)
    ("calculate", "Evaluate a math expression", []),
    ("translate", "Translate text between languages", []),
    ("get_weather", "Get the current weather for a city", []),
    ("post_process_document", "Post-process a document locally", []),
    ("internal_helper", "An internal utility function", []),
    ("roll_dice", "Roll a set of dice", []),
]


def _legs(name: str, desc: str) -> set[str]:
    return {s.leg.value for s in classify_server(ServerSurface("x", tools=[ToolInfo(name, desc)]))}


def _score():
    tp = fp = fn = 0
    mismatches = []
    for name, desc, expected in CORPUS:
        got, exp = _legs(name, desc), set(expected)
        tp += len(got & exp)
        fp += len(got - exp)
        fn += len(exp - got)
        if got != exp:
            mismatches.append((name, sorted(got), sorted(exp)))
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, fp, fn, mismatches


def test_classifier_precision_and_recall_bar():
    """After calibration the classifier clears a high bar on real MCP tools."""
    precision, recall, fp, fn, mismatches = _score()
    # Precision matters most: over-flagging erodes trust. Recall is high but the
    # heuristic is allowed a small tail (semantic-only cases a keyword cannot catch).
    assert precision >= 0.97, f"precision {precision:.3f} too low; false positives: {mismatches}"
    assert recall >= 0.92, f"recall {recall:.3f} too low; misses: {mismatches}"


def test_no_local_write_is_flagged_as_exfil():
    """The calibration's sharpest false-positive class: local writes are not exfil."""
    for name, desc in (
        ("write_file", "Write content to a local file"),
        ("create_directory", "Create a local directory"),
        ("save_note", "Save a note to the local vault"),
    ):
        assert E not in _legs(name, desc), name


def test_local_search_is_not_web_content():
    """The other sharp false positive: a local-store search is private, not untrusted."""
    for name, desc in (
        ("search_files", "Search local files"),
        ("search_nodes", "Search the knowledge graph"),
        ("gdrive_search", "Search the user's Drive"),
    ):
        legs = _legs(name, desc)
        assert U not in legs and P in legs, (name, legs)


def test_pure_reads_are_never_exfil():
    """Vendor-name literals must not turn reads into exfil channels."""
    for name, desc in (
        ("read_messages", "Read messages from a Discord channel"),
        ("get_chat", "Get Telegram chat metadata"),
        ("slack_get_users", "List Slack users"),
    ):
        assert E not in _legs(name, desc), name
