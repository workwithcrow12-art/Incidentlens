"""Lưu trữ: cảnh báo, sự cố, kết quả điều tra, phản hồi, nhật ký hành động.

Mặc định SQLite; dùng PostgreSQL khi chạy thật. Mọi thời gian đều lưu ở UTC.
"""

from __future__ import annotations

from datetime import datetime
from threading import Lock

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, create_engine, delete, func, or_, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import IntegrityError

from incidentlens.models import (
    ActionRecord,
    AlertRecord,
    IncidentRecord,
    Investigation,
    InvestigationRecord,
    RoutedAlert,
    Severity,
    as_utc,
)


class Base(DeclarativeBase):
    pass


def _ts(**kwargs):
    return mapped_column(DateTime(timezone=True), **kwargs)


class AlertRow(Base):
    __tablename__ = "alerts"

    fingerprint: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    service: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    labels: Mapped[dict] = mapped_column(JSON)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    receive_count: Mapped[int] = mapped_column(Integer)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    escalated_at: Mapped[datetime | None] = _ts(nullable=True)
    digested: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class EpisodeRow(Base):
    """Mỗi lần một cảnh báo bắt đầu xảy ra (không tính các lần gửi lại). Dùng cho báo cáo ROI."""

    __tablename__ = "episodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = _ts(index=True)
    fingerprint: Mapped[str] = mapped_column(String(128))
    service: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    service: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text)
    labels: Mapped[dict] = mapped_column(JSON)
    origin: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = _ts()
    opened_at: Mapped[datetime] = _ts(index=True)
    resolved_at: Mapped[datetime | None] = _ts(nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix: Mapped[str | None] = mapped_column(Text, nullable=True)


class InvestigationRow(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    created_at: Mapped[datetime] = _ts(index=True)
    data: Mapped[dict] = mapped_column(JSON)
    feedback: Mapped[str | None] = mapped_column(String(8), nullable=True)
    feedback_hypothesis: Mapped[int | None] = mapped_column(Integer, nullable=True)
    feedback_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    feedback_at: Mapped[datetime | None] = _ts(nullable=True)


class ActionRow(Base):
    """Nhật ký kiểm toán: ai bấm hành động gì, lúc nào, kết quả ra sao."""

    __tablename__ = "action_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = _ts()
    incident_id: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(64))
    service: Mapped[str] = mapped_column(String(255))
    user: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str] = mapped_column(Text, default="")


class KVRow(Base):
    __tablename__ = "kv"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class InteractionRow(Base):
    __tablename__ = "interaction_claims"

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    at: Mapped[datetime] = _ts()


class DeliveryRow(Base):
    __tablename__ = "notification_deliveries"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    channel: Mapped[str] = mapped_column(String(16))
    event: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict] = mapped_column(JSON)
    done: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


def _alert(row: AlertRow) -> AlertRecord:
    return AlertRecord(
        fingerprint=row.fingerprint, name=row.name, service=row.service, severity=Severity(row.severity),
        status=row.status, summary=row.summary, labels=row.labels or {}, source_url=row.source_url,
        first_seen=as_utc(row.first_seen), last_seen=as_utc(row.last_seen), receive_count=row.receive_count,
        escalated=row.escalated, escalated_at=as_utc(row.escalated_at),
    )


def _incident(row: IncidentRow) -> IncidentRecord:
    return IncidentRecord(
        id=row.id, fingerprint=row.fingerprint, service=row.service, name=row.name, summary=row.summary,
        labels=row.labels or {}, origin=row.origin, started_at=as_utc(row.started_at),
        opened_at=as_utc(row.opened_at), resolved_at=as_utc(row.resolved_at),
        root_cause=row.root_cause, fix=row.fix,
    )


def _investigation(row: InvestigationRow) -> InvestigationRecord:
    return InvestigationRecord(
        id=row.id, incident_id=row.incident_id, created_at=as_utc(row.created_at),
        investigation=Investigation.model_validate(row.data), feedback=row.feedback,
        feedback_hypothesis=row.feedback_hypothesis, feedback_by=row.feedback_by,
    )


def _action(row: ActionRow) -> ActionRecord:
    return ActionRecord(id=row.id, at=as_utc(row.at), incident_id=row.incident_id, action=row.action,
                        service=row.service, user=row.user, status=row.status, exit_code=row.exit_code,
                        output=row.output or "")


class Store:
    def __init__(self, url: str) -> None:
        kwargs: dict = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url or url == "sqlite://":
                kwargs["poolclass"] = StaticPool
        self._engine = create_engine(url, **kwargs)
        Base.metadata.create_all(self._engine)
        self._session = sessionmaker(self._engine, expire_on_commit=False)
        self._claim_lock = Lock()

    def claim_interaction(self, request_id: str, now: datetime) -> bool:
        # The unique key also arbitrates requests made through separate Store instances.
        with self._claim_lock:
            try:
                with self._session.begin() as session:
                    session.add(InteractionRow(request_id=request_id, at=as_utc(now)))
                return True
            except IntegrityError:
                return False

    def queue_delivery(self, key: str, fingerprint: str, incident_id: int | None,
                       channel: str, event: str, payload: dict, repeat: bool = False) -> None:
        with self._session.begin() as session:
            row = session.get(DeliveryRow, key)
            if row is None:
                session.add(DeliveryRow(key=key, fingerprint=fingerprint, incident_id=incident_id,
                                        channel=channel, event=event, payload=payload, done=False))
            elif repeat:
                row.done = False
                row.payload = payload

    def pending_deliveries(self, fingerprint: str | None = None) -> list[dict]:
        stmt = select(DeliveryRow).where(DeliveryRow.done.is_(False))
        if fingerprint is not None:
            stmt = stmt.where(DeliveryRow.fingerprint == fingerprint)
        with self._session() as session:
            rows = session.scalars(stmt).all()
            # PagerDuty goes first so a failed trigger can make the Slack message loud.
            rows.sort(key=lambda r: (r.channel != "pager", r.key))
            return [dict(key=r.key, fingerprint=r.fingerprint, incident_id=r.incident_id,
                         channel=r.channel, event=r.event, payload=r.payload) for r in rows]

    def finish_delivery(self, key: str) -> None:
        with self._session.begin() as session:
            session.execute(update(DeliveryRow).where(DeliveryRow.key == key).values(done=True))

    def pager_key(self, incident: IncidentRecord) -> str:
        with self._session() as session:
            row = session.get(DeliveryRow, f"incident:{incident.id}:open:pager")
            # Incidents created before delivery tracking used the bare fingerprint.
            return row.payload["dedup_key"] if row else incident.fingerprint

    def cancel_deliveries(self, fingerprint: str, event: str | None = None) -> None:
        stmt = update(DeliveryRow).where(DeliveryRow.fingerprint == fingerprint)
        if event is not None:
            stmt = stmt.where(DeliveryRow.event == event)
        with self._session.begin() as session:
            session.execute(stmt.values(done=True))

    # ---------- Cảnh báo ----------

    def record(self, routed: RoutedAlert, now: datetime) -> AlertRecord | None:
        """Ghi nhận một cảnh báo vừa nhận. Trả về trạng thái sau khi cập nhật."""
        alert = routed.alert
        now = as_utc(now)
        # Dùng thời điểm sự cố thật sự bắt đầu (startsAt), không phải lúc nhận được
        started = min(alert.starts_at, now)
        with self._session.begin() as session:
            row = session.get(AlertRow, alert.fingerprint)
            is_new = row is None
            if row is not None:
                previous_start = as_utc(row.first_seen)
                if started < previous_start or (started == previous_start and row.status == "resolved"
                                                 and alert.status == "firing"):
                    return None  # Late delivery from an older or already recovered episode.
            if row is None:
                row = AlertRow(fingerprint=alert.fingerprint, first_seen=started, receive_count=0,
                               escalated=False, digested=False)
                session.add(row)
            elif started > as_utc(row.first_seen):
                # Cùng cảnh báo nhưng xảy ra lại: bắt đầu một đợt mới
                row.first_seen = started
                row.receive_count = 0
                row.escalated = False
                row.escalated_at = None
                row.digested = False

            if row.status == "firing" and alert.status == "resolved":
                row.digested = False

            row.name = alert.name
            row.service = alert.service
            row.summary = alert.summary
            row.source_url = alert.source_url
            row.labels = alert.labels
            row.status = alert.status
            row.last_seen = alert.ends_at or now
            row.severity = routed.severity.value
            if alert.status == "firing" or is_new:
                row.receive_count += 1
            session.flush()
            return _alert(row)

    def get(self, fingerprint: str) -> AlertRecord | None:
        with self._session() as session:
            row = session.get(AlertRow, fingerprint)
            return _alert(row) if row else None

    def firing_alerts(self, service: str) -> list[AlertRecord]:
        stmt = select(AlertRow).where(AlertRow.service == service, AlertRow.status == "firing")
        with self._session() as session:
            return [_alert(r) for r in session.scalars(stmt)]

    def pending_for_digest(self) -> list[AlertRecord]:
        """Cảnh báo 🟡⚪ chưa được đưa vào digest, hoặc vẫn đang xảy ra."""
        stmt = (
            select(AlertRow)
            .where(AlertRow.severity.in_([Severity.ACTION.value, Severity.INFO.value]))
            .where(or_(AlertRow.digested.is_(False), AlertRow.status == "firing"))
            .order_by(AlertRow.first_seen)
        )
        with self._session() as session:
            return [_alert(r) for r in session.scalars(stmt)]

    def mark_digested(self, fingerprints: list[str]) -> None:
        if not fingerprints:
            return
        with self._session.begin() as session:
            session.execute(update(AlertRow).where(AlertRow.fingerprint.in_(fingerprints)).values(digested=True))

    def mark_digest_snapshot(self, records: list[AlertRecord]) -> None:
        with self._session.begin() as session:
            for record in records:
                session.execute(update(AlertRow).where(
                    AlertRow.fingerprint == record.fingerprint, AlertRow.first_seen == record.first_seen,
                    AlertRow.last_seen == record.last_seen, AlertRow.status == record.status,
                    AlertRow.receive_count == record.receive_count).values(digested=True))

    def escalation_candidates(self) -> list[AlertRecord]:
        stmt = select(AlertRow).where(
            AlertRow.severity == Severity.ACTION.value, AlertRow.status == "firing", AlertRow.escalated.is_(False)
        )
        with self._session() as session:
            return [_alert(r) for r in session.scalars(stmt)]

    def mark_escalated(self, fingerprint: str, now: datetime) -> None:
        with self._session.begin() as session:
            session.execute(update(AlertRow).where(AlertRow.fingerprint == fingerprint)
                            .values(escalated=True, escalated_at=as_utc(now)))

    # ---------- Đợt cảnh báo (cho báo cáo) ----------

    def log_episode(self, record: AlertRecord, now: datetime) -> None:
        with self._session.begin() as session:
            session.add(EpisodeRow(at=as_utc(now), fingerprint=record.fingerprint, service=record.service,
                                   severity=record.severity.value))

    def count_episodes(self, start: datetime, end: datetime) -> int:
        stmt = select(func.count()).select_from(EpisodeRow).where(EpisodeRow.at >= as_utc(start),
                                                                 EpisodeRow.at < as_utc(end))
        with self._session() as session:
            return session.scalar(stmt) or 0

    # ---------- Sự cố ----------

    def open_incident(self, record: AlertRecord, origin: str, now: datetime) -> tuple[IncidentRecord, bool]:
        """Mở sự cố cho cảnh báo. Nếu đã có sự cố đang mở thì trả về nó (created=False)."""
        with self._session.begin() as session:
            row = session.scalars(select(IncidentRow).where(
                IncidentRow.fingerprint == record.fingerprint, IncidentRow.resolved_at.is_(None))).first()
            if row is not None:
                return _incident(row), False
            row = IncidentRow(fingerprint=record.fingerprint, service=record.service, name=record.name,
                              summary=record.summary, labels=record.labels, origin=origin,
                              started_at=as_utc(record.first_seen), opened_at=as_utc(now))
            session.add(row)
            session.flush()
            return _incident(row), True

    def close_incident(self, fingerprint: str, resolved_at: datetime) -> IncidentRecord | None:
        with self._session.begin() as session:
            row = session.scalars(select(IncidentRow).where(
                IncidentRow.fingerprint == fingerprint, IncidentRow.resolved_at.is_(None))).first()
            if row is None:
                return None
            row.resolved_at = max(as_utc(resolved_at), as_utc(row.started_at))
            session.flush()
            return _incident(row)

    def get_incident(self, incident_id: int) -> IncidentRecord | None:
        with self._session() as session:
            row = session.get(IncidentRow, incident_id)
            return _incident(row) if row else None

    def episode_incident(self, fingerprint: str, started_at: datetime) -> IncidentRecord | None:
        with self._session() as session:
            row = session.scalars(select(IncidentRow).where(
                IncidentRow.fingerprint == fingerprint, IncidentRow.started_at == as_utc(started_at)
            ).order_by(IncidentRow.id.desc())).first()
            return _incident(row) if row else None

    def list_incidents(self, limit: int = 50) -> list[IncidentRecord]:
        stmt = select(IncidentRow).order_by(IncidentRow.opened_at.desc()).limit(limit)
        with self._session() as session:
            return [_incident(r) for r in session.scalars(stmt)]

    def closed_incidents(self, limit: int = 500) -> list[IncidentRecord]:
        stmt = (select(IncidentRow).where(IncidentRow.resolved_at.is_not(None))
                .order_by(IncidentRow.resolved_at.desc()).limit(limit))
        with self._session() as session:
            return [_incident(r) for r in session.scalars(stmt)]

    def incidents_between(self, start: datetime, end: datetime) -> list[IncidentRecord]:
        stmt = select(IncidentRow).where(IncidentRow.opened_at >= as_utc(start), IncidentRow.opened_at < as_utc(end))
        with self._session() as session:
            return [_incident(r) for r in session.scalars(stmt)]

    def set_resolution(self, incident_id: int, root_cause: str | None = None, fix: str | None = None,
                       only_if_empty: bool = False) -> IncidentRecord | None:
        with self._session.begin() as session:
            row = session.get(IncidentRow, incident_id)
            if row is None:
                return None
            if root_cause and not (only_if_empty and row.root_cause):
                row.root_cause = root_cause
            if fix and not (only_if_empty and row.fix):
                row.fix = fix
            session.flush()
            return _incident(row)

    # ---------- Điều tra và phản hồi ----------

    def save_investigation(self, investigation: Investigation, incident_id: int | None,
                           now: datetime) -> InvestigationRecord:
        with self._session.begin() as session:
            row = InvestigationRow(incident_id=incident_id, created_at=as_utc(now),
                                   data=investigation.model_dump(mode="json"))
            session.add(row)
            session.flush()
            return _investigation(row)

    def get_investigation(self, investigation_id: int) -> InvestigationRecord | None:
        with self._session() as session:
            row = session.get(InvestigationRow, investigation_id)
            return _investigation(row) if row else None

    def investigations_for_incident(self, incident_id: int) -> list[InvestigationRecord]:
        stmt = (select(InvestigationRow).where(InvestigationRow.incident_id == incident_id)
                .order_by(InvestigationRow.created_at))
        with self._session() as session:
            return [_investigation(r) for r in session.scalars(stmt)]

    def investigations_between(self, start: datetime, end: datetime) -> list[InvestigationRecord]:
        stmt = select(InvestigationRow).where(InvestigationRow.created_at >= as_utc(start),
                                              InvestigationRow.created_at < as_utc(end))
        with self._session() as session:
            return [_investigation(r) for r in session.scalars(stmt)]

    def set_feedback(self, investigation_id: int, verdict: str, hypothesis: int | None, user: str,
                     now: datetime) -> None:
        with self._session.begin() as session:
            session.execute(update(InvestigationRow).where(InvestigationRow.id == investigation_id).values(
                feedback=verdict, feedback_hypothesis=hypothesis, feedback_by=user, feedback_at=as_utc(now)))

    # ---------- Nhật ký hành động ----------

    def log_action(self, now: datetime, incident_id: int, action: str, service: str, user: str, status: str,
                   exit_code: int | None, output: str) -> None:
        with self._session.begin() as session:
            session.add(ActionRow(at=as_utc(now), incident_id=incident_id, action=action, service=service,
                                  user=user, status=status, exit_code=exit_code, output=output))

    def actions_for_incident(self, incident_id: int) -> list[ActionRecord]:
        stmt = select(ActionRow).where(ActionRow.incident_id == incident_id).order_by(ActionRow.at)
        with self._session() as session:
            return [_action(r) for r in session.scalars(stmt)]

    # ---------- Trạng thái nhỏ và dọn dẹp ----------

    def kv_get(self, key: str) -> str | None:
        with self._session() as session:
            row = session.get(KVRow, key)
            return row.value if row else None

    def kv_set(self, key: str, value: str) -> None:
        with self._session.begin() as session:
            row = session.get(KVRow, key)
            if row is None:
                session.add(KVRow(key=key, value=value))
            else:
                row.value = value

    def purge(self, before: datetime) -> dict[str, int]:
        """Xóa cảnh báo đã hồi phục + đã vào digest và các đợt cảnh báo cũ hơn `before`.

        Sự cố, kết quả điều tra và nhật ký hành động được GIỮ LẠI: đó là trí nhớ và dữ liệu kiểm toán.
        """
        before = as_utc(before)
        with self._session.begin() as session:
            alerts = session.execute(delete(AlertRow).where(
                AlertRow.status == "resolved", AlertRow.digested.is_(True), AlertRow.last_seen < before))
            episodes = session.execute(delete(EpisodeRow).where(EpisodeRow.at < before))
            return {"alerts": alerts.rowcount or 0, "episodes": episodes.rowcount or 0}


AlertStore = Store  # tên cũ, giữ để tương thích
