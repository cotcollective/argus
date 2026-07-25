"""Phone reconnaissance module — libphonenumber local (no API key)."""

import re
from argus.core.base import BaseModule, Finding
from argus.core.registry import Registry


@Registry.register
class PhoneReconModule(BaseModule):
    name = "phone"
    description = "Phone number intelligence via libphonenumber (local, no API key)"
    input_type = "phone"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target = target.strip()

        # Try phonenumbers library (Google libphonenumber port)
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone

            # Parse phone number
            if not target.startswith("+"):
                target = "+" + target
            number = phonenumbers.parse(target)

            if not phonenumbers.is_valid_number(number):
                findings.append(Finding(
                    module=self.name, target=target,
                    key="result", value="Invalid phone number",
                ))
                return findings

            # Basic info
            findings.append(Finding(
                module=self.name, target=target,
                key="info", value=f"{phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}",
                extra={
                    "country_code": number.country_code,
                    "national_number": number.national_number,
                    "valid": True,
                    "possible": phonenumbers.is_possible_number(number),
                },
            ))

            # Carrier
            try:
                c = carrier.name_for_number(number, "en")
                if c:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="carrier", value=c,
                    ))
            except Exception:
                pass

            # Location
            try:
                loc = geocoder.description_for_number(number, "en")
                if loc:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="location", value=loc,
                    ))
            except Exception:
                pass

            # Timezone
            try:
                tz = timezone.time_zones_for_number(number)
                if tz:
                    findings.append(Finding(
                        module=self.name, target=target,
                        key="timezone", value=", ".join(tz),
                    ))
            except Exception:
                pass

            # Line type
            try:
                lt = phonenumbers.number_type(number)
                line_types = {
                    0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
                    3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
                    6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
                    9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN",
                }
                lt_name = line_types.get(lt, f"UNKNOWN({lt})")
                findings.append(Finding(
                    module=self.name, target=target,
                    key="line_type", value=lt_name,
                ))
            except Exception:
                pass

        except ImportError:
            # phonenumbers not installed
            # Fallback: basic regex parsing
            findings.append(Finding(
                module=self.name, target=target,
                key="info", value=target,
                extra={
                    "note": "Install phonenumbers for full analysis: pip install phonenumbers",
                    "country_code": re.match(r'\+(\d{1,3})', target).group(1) if re.match(r'\+(\d{1,3})', target) else "unknown",
                },
            ))
        except Exception as e:
            findings.append(Finding(
                module=self.name, target=target,
                key="error", value=str(e),
            ))

        return findings