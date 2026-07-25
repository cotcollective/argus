"""Breach check module — local SQLite breach database (replaces HIBP API)."""

import sqlite3
import os
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry
from argus.config import config


@Registry.register
class BreachCheckModule(BaseModule):
    name = "breach"
    description = "Check email against local breach database (replaces HIBP API)"
    input_type = "email"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        db_path = config.breach_db

        if not os.path.exists(db_path):
            # No local DB, fallback to public breach compilation search
            return self._fallback_dehashed(target)

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check if email exists in any breach table
            cursor.execute(
                "SELECT breach_name, date, data_classes FROM breaches WHERE email = ?",
                (target.lower(),),
            )
            rows = cursor.fetchall()
            conn.close()

            if rows:
                for row in rows:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="breach", value=row[0],
                        extra={
                            "date": row[1],
                            "data_classes": row[2],
                            "source": "local breach DB",
                        },
                    ))
            else:
                findings.append(Finding(
                    module=self.name, target=target,
                    key="result", value="No breaches found in local DB",
                ))
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))

        return findings

    def _fallback_dehashed(self, target: str) -> list[Finding]:
        """Fallback: note that local DB not configured."""
        return [Finding(
            module=self.name, target=target,
            key="info",
            value="No local breach DB configured. Download breach compilations to ~/.argus/breaches.db",
            extra={
                "setup": "Download breach data from open-source compilations, import to SQLite",
                "schema": "CREATE TABLE breaches (email TEXT, breach_name TEXT, date TEXT, data_classes TEXT)",
            },
        )]