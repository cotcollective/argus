"""Google dork generator — generates targeted search URLs, no network calls."""

from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class DorkGeneratorModule(BaseModule):
    name = "dorks"
    description = "Generate targeted Google dork URLs (no network calls)"
    input_type = "auto"

    DORK_TEMPLATES = [
        ('"{target}" site:linkedin.com', 'LinkedIn mentions'),
        ('"{target}" site:github.com', 'GitHub mentions'),
        ('"{target}" site:twitter.com OR site:x.com', 'Twitter/X mentions'),
        ('"{target}" site:reddit.com', 'Reddit mentions'),
        ('"{target}" site:pastebin.com', 'Pastebin mentions'),
        ('"{target}" leaked OR breach OR dump OR password', 'Leak/breach mentions'),
        ('"{target}" site:facebook.com OR site:instagram.com', 'Social media'),
        ('"{target}" filetype:pdf', 'PDF documents'),
        ('"{target}" filetype:doc OR filetype:docx', 'Word documents'),
        ('"{target}" intext:"password" OR intext:"confidential"', 'Sensitive content'),
        ('"{target}" site:youtube.com', 'YouTube mentions'),
        ('"{target}" inurl:admin OR inurl:login OR inurl:dashboard', 'Admin panels'),
    ]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target_clean = target.strip()

        for dork, desc in self.DORK_TEMPLATES:
            query = dork.format(target=target_clean)
            q = query.replace(' ', '+').replace('"', '%22').replace(':', '%3A')
            url = f"https://www.google.com/search?q={q}"
            findings.append(Finding(
                module=self.name, target=target_clean,
                key=desc, value=url,
                extra={"dork_query": query},
            ))

        return findings