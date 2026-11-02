"""BTF services (EBICS 3.0 business transaction formats) with presets for CH and DE."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, ClassVar

__all__ = ["Service"]


@dataclass(frozen=True)
class Service:
    """A BTF Service: what a BTD downloads or a BTU uploads.

    Fields map onto RestrictedServiceType in ebics_orders_H005.xsd, in schema order:
    ServiceName (name), Scope (scope), ServiceOption (option), Container
    (container: "ZIP", "XML" or "SVC"), MsgName (msg_name) with its version,
    variant and format attributes. Banks publish the services they support (HAA
    order type, or their EBICS documentation); use dataclasses.replace or
    Service.with_ to adapt a preset.
    """

    name: str
    msg_name: str
    scope: str | None = None
    option: str | None = None
    container: str | None = None
    msg_version: str | None = None
    variant: str | None = None
    format: str | None = None

    def __post_init__(self) -> None:
        if len(self.name) != 3 or not self.name.isalnum() or not self.name.isupper():
            raise ValueError(f"ServiceName must be 3 upper case characters, got {self.name!r}")
        if self.container not in (None, "ZIP", "XML", "SVC"):
            raise ValueError(f"Container must be ZIP, XML or SVC, got {self.container!r}")

    def with_(self, **changes: Any) -> Service:
        """Return a copy with some fields changed, e.g. CAMT_053_CH.with_(msg_version="04")."""
        return replace(self, **changes)

    #: camt.052 intraday report, Switzerland (Z52). Source: Swiss Payment Standards,
    #: Swiss Implementation Guidelines for EBICS, BTF mapping of Z52.
    CAMT_052_CH: ClassVar[Service]
    #: camt.053 end of day statement, Switzerland (Z53). Source: Swiss Payment
    #: Standards, Swiss Implementation Guidelines for EBICS, BTF mapping of Z53.
    CAMT_053_CH: ClassVar[Service]
    #: camt.054 debit/credit notification, Switzerland (Z54). Source: Swiss Payment
    #: Standards, Swiss Implementation Guidelines for EBICS, BTF mapping of Z54.
    CAMT_054_CH: ClassVar[Service]
    #: pain.001 credit transfer, Switzerland (XE2). Source: Swiss Payment Standards,
    #: Swiss Implementation Guidelines for EBICS, BTF mapping of XE2.
    PAIN_001_CH: ClassVar[Service]
    #: pain.008 direct debit, Switzerland (XE3). Source: Swiss Payment Standards,
    #: Swiss Implementation Guidelines for EBICS, BTF mapping of XE3.
    PAIN_008_CH: ClassVar[Service]
    #: camt.052 intraday report, Germany (C52). Source: DK EBICS specification,
    #: Annex 3 (BTF order type mapping), C52.
    CAMT_052_DE: ClassVar[Service]
    #: camt.053 statement, Germany (C53). Source: DK Annex 3, C53.
    CAMT_053_DE: ClassVar[Service]
    #: camt.054 notification, Germany (C54). Source: DK Annex 3, C54.
    CAMT_054_DE: ClassVar[Service]
    #: SEPA credit transfer pain.001, Germany (CCT). Source: DK Annex 3, CCT.
    PAIN_001_DE: ClassVar[Service]
    #: SEPA core direct debit pain.008, Germany (CDD). Source: DK Annex 3, CDD.
    PAIN_008_DE: ClassVar[Service]


# Swiss presets: Swiss Payment Standards, "Swiss Implementation Guidelines for EBICS"
# (SIX), BTF mapping for the Swiss order types Z52, Z53, Z54, XE2 and XE3, with the
# message versions of SPS 2022+ (camt.05x.001.08, pain.001.001.09, pain.008.001.08).
Service.CAMT_052_CH = Service("STM", "camt.052", scope="CH", container="ZIP", msg_version="08")
Service.CAMT_053_CH = Service("EOP", "camt.053", scope="CH", container="ZIP", msg_version="08")
Service.CAMT_054_CH = Service("REP", "camt.054", scope="CH", container="ZIP", msg_version="08")
Service.PAIN_001_CH = Service("MCT", "pain.001", scope="CH", msg_version="09")
Service.PAIN_008_CH = Service("SDD", "pain.008", scope="CH", msg_version="08")

# German presets: DK (German Banking Industry Committee) Annex 3 of the EBICS
# interface specification, BTF mapping of C52, C53, C54, CCT and CDD.
Service.CAMT_052_DE = Service("STM", "camt.052", scope="DE", container="ZIP")
Service.CAMT_053_DE = Service("EOP", "camt.053", scope="DE", container="ZIP")
Service.CAMT_054_DE = Service("REP", "camt.054", scope="DE", container="ZIP")
Service.PAIN_001_DE = Service("SCT", "pain.001", scope="DE")
Service.PAIN_008_DE = Service("SDD", "pain.008", scope="DE", option="COR")
