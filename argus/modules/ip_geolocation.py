"""IP geolocation module — MaxMind GeoLite2 local database (no API key)."""

import json
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry
from argus.config import config


@Registry.register
class IPGeolocationModule(BaseModule):
    name = "ipgeo"
    description = "IP geolocation via MaxMind GeoLite2 local DB (replaces IP2Location API)"
    input_type = "ip"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        # Try maxminddb if available
        try:
            import maxminddb
            db_path = config.geolite2_db
            import os
            if not os.path.exists(db_path):
                # Fallback to ipinfo.io free tier (50k/month, no key)
                return self._fallback_ipinfo(target)

            with maxminddb.open_database(db_path) as reader:
                result = reader.get(target)
                if result:
                    city = result.get("city", {}).get("names", {}).get("en", "N/A")
                    country = result.get("country", {}).get("names", {}).get("en", "N/A")
                    country_code = result.get("country", {}).get("iso_code", "N/A")
                    lat = result.get("location", {}).get("latitude", "N/A")
                    lon = result.get("location", {}).get("longitude", "N/A")
                    timezone = result.get("location", {}).get("time_zone", "N/A")
                    asn = result.get("autonomous_system_number", "N/A")
                    org = result.get("autonomous_system_organization", "N/A")

                    findings.append(Finding(
                        module=self.name, target=target,
                        key="geolocation", value=f"{city}, {country} ({country_code})",
                        extra={
                            "latitude": lat, "longitude": lon,
                            "timezone": timezone, "asn": asn, "org": org,
                            "source": "GeoLite2 local DB",
                        },
                    ))
                else:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="result", value="IP not found in GeoLite2 DB",
                    ))
        except ImportError:
            # maxminddb not installed, fallback to ipinfo.io
            return self._fallback_ipinfo(target)
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))

        return findings

    def _fallback_ipinfo(self, target: str) -> list[Finding]:
        """Fallback to ipinfo.io free tier (50k/month, no API key)."""
        import requests
        findings = []
        try:
            resp = requests.get(
                f"https://ipinfo.io/{target}/json",
                headers={"User-Agent": "curl/8.5.0"},
                timeout=config.timeout,
            )
            data = resp.json()
            findings.append(Finding(
                module=self.name, target=target,
                key="geolocation",
                value=f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}",
                extra={
                    "region": data.get("region"),
                    "org": data.get("org"),
                    "hostname": data.get("hostname"),
                    "loc": data.get("loc"),
                    "timezone": data.get("timezone"),
                    "source": "ipinfo.io free tier",
                },
            ))
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))
        return findings