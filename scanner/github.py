"""
scanner.github — GitHub API integration: repository discovery and clone URL generation.
"""
import requests

from scanner.config import (
    GITHUB_TOKEN,
    GITHUB_USER,
    GITHUB_ORG,
    GITHUB_REPOS,
)
from scanner.logging_setup import logger

_GITHUB_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}


def get_github_headers():
    """Return the standard GitHub API request headers."""
    return _GITHUB_HEADERS


def fetch_repositories():
    """Fetch repositories from GitHub based on configuration."""
    headers = get_github_headers()

    if GITHUB_REPOS:
        repos_list = [r.strip() for r in GITHUB_REPOS.split(",") if r.strip()]
        logger.info(f"Scanning specified repositories: {repos_list}")
        repos = []
        for repo_name in repos_list:
            url = f"https://api.github.com/repos/{repo_name}"
            res = requests.get(url, headers=headers)
            if res.status_code == 200:
                repos.append(res.json())
            else:
                logger.error(f"Failed to fetch repository {repo_name}: {res.status_code} - {res.text}")
        return repos

    repos = []
    if GITHUB_ORG:
        url = f"https://api.github.com/orgs/{GITHUB_ORG}/repos"
        logger.info(f"Fetching all repositories for organization: {GITHUB_ORG}")
    elif GITHUB_USER:
        url = f"https://api.github.com/users/{GITHUB_USER}/repos"
        logger.info(f"Fetching all public repositories for user: {GITHUB_USER}")
    else:
        url = "https://api.github.com/user/repos"
        logger.info("Fetching all accessible repositories for authenticated user")

    params = {"per_page": 100, "page": 1, "type": "all"}
    while True:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code != 200:
            logger.error(f"GitHub API Error: {res.status_code} - {res.text}")
            raise Exception("Failed to list GitHub repositories")

        page_repos = res.json()
        if not page_repos:
            break
        repos.extend(page_repos)
        params["page"] += 1

    logger.info(f"Discovered {len(repos)} repositories to process")
    return repos


def get_auth_clone_url(repo):
    """Generate authenticated URL for cloning private repositories."""
    raw_url = repo['clone_url']
    if raw_url.startswith("https://github.com/"):
        return raw_url.replace("https://github.com/", f"https://x-access-token:{GITHUB_TOKEN}@github.com/")
    return raw_url
