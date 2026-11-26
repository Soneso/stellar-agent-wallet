"""Documentation paths shared by the change classifier and read checker."""


def is_documentation(path):
    """Whether one repository-relative path is a documentation path."""
    if not path.endswith(".md"):
        return False
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    if len(parts) == 1:
        return True
    if parts[0] == "docs":
        return True
    if parts[0] == "changelog.d":
        return len(parts) == 2
    return parts[:2] == ["skills", "stellar-agent-wallet"] and len(parts) > 2


def is_docs_only_path(path):
    """Whether a path qualifies for docs-only CI, including the PR template."""
    return path == ".github/PULL_REQUEST_TEMPLATE.md" or is_documentation(path)
