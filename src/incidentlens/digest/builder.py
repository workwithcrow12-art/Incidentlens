"""Gom các cảnh báo thành từng mục để hiển thị trong digest."""

from __future__ import annotations

from collections import defaultdict

from incidentlens.catalog import ServiceCatalog
from incidentlens.models import AlertGroup, AlertRecord


def group_alerts(records: list[AlertRecord], catalog: ServiceCatalog) -> list[AlertGroup]:
    """Nhóm theo (dịch vụ, loại cảnh báo). Sắp xếp: mức cao → đang xảy ra → nhiều cảnh báo."""
    groups: dict[tuple[str, str], list[AlertRecord]] = defaultdict(list)
    for record in records:
        groups[(record.service, record.name)].append(record)

    result = [
        AlertGroup(service=service, name=name, team=catalog.get(service).team, records=items)
        for (service, name), items in groups.items()
    ]
    result.sort(key=lambda g: (-g.severity.rank, not g.is_ongoing, -g.receive_count))
    return result
