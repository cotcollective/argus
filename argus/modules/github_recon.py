"""GitHub reconnaissance module — uses GitHub REST API (free, 60 req/min without token)."""

import requests
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry
from argus.config import config


@Registry.register
class GitHubReconModule(BaseModule):
    name = "github"
    description = "GitHub OSINT: profile, repos, commit-email discovery"
    input_type = "username"

    API_BASE = "https://api.github.com"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        headers = {"Accept": "application/vnd.github+json", "User-Agent": config.user_agent}
        if config.github_token:
            headers["Authorization"] = f"Bearer {config.github_token}"

        # User profile
        try:
            resp = requests.get(f"{self.API_BASE}/users/{target}", headers=headers, timeout=config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                findings.append(Finding(
                    module=self.name, target=target,
                    key="profile", value=data.get("html_url", ""),
                    extra={
                        "name": data.get("name"),
                        "bio": data.get("bio"),
                        "company": data.get("company"),
                        "location": data.get("location"),
                        "email": data.get("email"),
                        "blog": data.get("blog"),
                        "public_repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                        "created_at": data.get("created_at"),
                    },
                ))
            elif resp.status_code == 404:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="result", value="GitHub user not found",
                ))
                return findings
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=f"Profile lookup failed: {e}",
            ))
            return findings

        # Repos (top 10 by stars)
        try:
            resp = requests.get(
                f"{self.API_BASE}/users/{target}/repos",
                headers=headers, timeout=config.timeout,
                params={"sort": "updated", "per_page": 10},
            )
            if resp.status_code == 200:
                repos = resp.json()
                for repo in repos[:10]:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key=f"repo", value=repo.get("html_url", ""),
                        extra={
                            "name": repo.get("name"),
                            "stars": repo.get("stargazers_count"),
                            "language": repo.get("language"),
                            "description": repo.get("description"),
                            "fork": repo.get("fork"),
                        },
                    ))
        except Exception:
            pass

        # Commit emails (discover emails from public commits)
        try:
            resp = requests.get(
                f"{self.API_BASE}/users/{target}/events/public",
                headers=headers, timeout=config.timeout,
                params={"per_page": 30},
            )
            if resp.status_code == 200:
                events = resp.json()
                seen_emails = set()
                for event in events:
                    if event.get("type") == "PushEvent":
                        commits = event.get("payload", {}).get("commits", [])
                        for commit in commits:
                            author = commit.get("author", {})
                            email = author.get("email")
                            if email and email not in seen_emails and "@noreply.github.com" not in email:
                                seen_emails.add(email)
                                findings.append(Finding(
                                    module=self.name, target=target,
                                    key="commit_email", value=email,
                                    extra={"repo": event.get("repo", {}).get("name")},
                                ))
        except Exception:
            pass

        return findings