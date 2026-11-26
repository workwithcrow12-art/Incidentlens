"""Group stored alerts into digest items."""

from __future__ import annotations

from collections import defaultdict

from incidentlens.catalog import ServiceCatalog
from incidentlens.models import AlertGroup, AlertRecord


def group_alerts(records: list[AlertRecord], catalog: ServiceCatalog) -> list[AlertGroup]:
    """Group by (service, alert name), sorted by severity, ongoing status, and receive count."""
    groups: dict[tuple[str, str], list[AlertRecord]] = defaultdict(list)
    for record in records:
        groups[(record.service, record.name)].append(record)

    result = [
        AlertGroup(service=service, name=name, team=catalog.get(service).team, records=items)
        for (service, name), items in groups.items()
    ]
    result.sort(key=lambda g: (-g.severity.rank, not g.is_ongoing, -g.receive_count))
    return result
