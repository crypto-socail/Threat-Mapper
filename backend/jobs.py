import asyncio
import json
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import models
from auth import decrypt_secret
from connectors import fetch_abuseipdb, fetch_hibp, fetch_misp, fetch_urlhaus, fetch_virustotal
from database import SessionLocal
from engine import evaluate_sources
from siem import push_to_splunk

scheduler = AsyncIOScheduler()
SEVERITY_RANK = {"not currently known as bad": 0, "suspicious": 1, "malicious": 2}


async def scan_watchlist():
    now = datetime.now(timezone.utc)
    print(f"\n[{now.isoformat()}] INTERVAL JOB: Scanning database watchlist...", flush=True)

    db = SessionLocal()
    try:
        watchlist = db.query(models.WatchlistRecord).all()
        records_to_scan = [
            {
                "id": r.id,
                "ioc_value": r.ioc_value,
                "ioc_type": r.ioc_type,
                "org_id": r.org_id,
                "alert_on_change": r.alert_on_change,
            }
            for r in watchlist
        ]
    except Exception as e:
        print(f" -> [ERROR] DB ERROR: {e}", flush=True)
        return
    finally:
        db.close()

    if not records_to_scan:
        return

    for record in records_to_scan:
        results = await asyncio.gather(
            fetch_virustotal(record["ioc_value"], record["ioc_type"]),
            fetch_abuseipdb(record["ioc_value"], record["ioc_type"]),
            fetch_urlhaus(record["ioc_value"], record["ioc_type"]),
            fetch_misp(record["ioc_value"], record["ioc_type"]),
            fetch_hibp(record["ioc_value"], record["ioc_type"]),
        )
        live_source_results = dict(zip(["virustotal", "abuseipdb", "urlhaus", "misp", "hibp"], results))
        score, verdict, _, _ = evaluate_sources(live_source_results)

        update_db = SessionLocal()
        try:
            db_record = (
                update_db.query(models.WatchlistRecord)
                .filter(models.WatchlistRecord.id == record["id"])
                .first()
            )
            if db_record:
                db_record.last_checked = datetime.now(timezone.utc)

            # Sync global IOC cache so /api/feed reflects live watchlist verdicts
            cached_ioc = (
                update_db.query(models.IOCRecord)
                .filter(models.IOCRecord.ioc_value == record["ioc_value"])
                .first()
            )
            prev_verdict = cached_ioc.verdict if cached_ioc else "not currently known as bad"

            if cached_ioc:
                cached_ioc.verdict = verdict
                cached_ioc.confidence_score = score
                cached_ioc.source_breakdown = json.dumps(live_source_results)
                cached_ioc.last_seen = datetime.now(timezone.utc)
            else:
                update_db.add(
                    models.IOCRecord(
                        ioc_value=record["ioc_value"],
                        ioc_type=record["ioc_type"],
                        verdict=verdict,
                        confidence_score=score,
                        source_breakdown=json.dumps(live_source_results),
                    )
                )

            # Persist DB alert and fire SIEM push only on verdict escalation
            escalated = SEVERITY_RANK.get(verdict, 0) > SEVERITY_RANK.get(prev_verdict, 0)
            if record["alert_on_change"] and escalated and verdict in ("suspicious", "malicious"):
                alert_msg = f"Watchlist IOC {record['ioc_value']} escalated to {verdict.upper()} (score: {score})"
                update_db.add(
                    models.AlertRecord(
                        org_id=record["org_id"],
                        ioc_value=record["ioc_value"],
                        ioc_type=record["ioc_type"],
                        threat_score=score,
                        message=alert_msg,
                    )
                )

                siem_config = (
                    update_db.query(models.SiemConfigRecord)
                    .filter(
                        models.SiemConfigRecord.org_id == record["org_id"],
                        models.SiemConfigRecord.siem_type == "splunk",
                    )
                    .first()
                )
                if siem_config and siem_config.endpoint_url:
                    await push_to_splunk(
                        endpoint_url=siem_config.endpoint_url,
                        auth_token=decrypt_secret(siem_config.auth_token),
                        ioc_data={
                            "ioc_value": record["ioc_value"],
                            "ioc_type": record["ioc_type"],
                            "verdict": verdict,
                            "confidence_score": score,
                        },
                    )

            update_db.commit()
        except Exception as e:
            update_db.rollback()
            print(f"        -> [ERROR] DB/Alert Error: {e}", flush=True)
        finally:
            update_db.close()


def run_retention_cleanup():
    db = SessionLocal()
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
        deleted_iocs = db.query(models.IOCRecord).filter(models.IOCRecord.last_seen < cutoff_date).delete()
        deleted_alerts = db.query(models.AlertRecord).filter(models.AlertRecord.created_at < cutoff_date).delete()
        db.commit()
        print(f" -> [SUCCESS] Purged {deleted_iocs} old IOCs and {deleted_alerts} old alerts.", flush=True)
    except Exception as e:
        print(f" -> [ERROR] Cleanup Job Failed: {e}", flush=True)
        db.rollback()
    finally:
        db.close()


def start_scheduler():
    scheduler.add_job(scan_watchlist, "interval", minutes=3)
    scheduler.add_job(run_retention_cleanup, "cron", hour=0, minute=0)
    scheduler.start()