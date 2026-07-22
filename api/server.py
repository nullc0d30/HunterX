# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import time

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from api.job_queue import queue
from api.models import ScanStatus
from core.engine import Engine
from core.report import Reporter
from core.utils import logger
from core.legal import get_json_metadata

app = None

if HAS_FASTAPI:
    app = FastAPI(title="HunterX API", version="4.0")

    class ScanRequest(BaseModel):
        url: str
        profile: str = "bounty"
        threads: int = 5
        stealth: str = "medium"
        passive_only: bool = False
        dry_run: bool = False
        output_dir: str = "reports"
        insecure: bool = False

    class ScanResponse(BaseModel):
        job_id: str
        status: str
        message: str

    def _run_scan_async(job_id: str, payloads: list, target_url: str, options: dict):
        try:
            queue.update(job_id, status=ScanStatus.RUNNING, progress=0.0)
            engine = Engine(target_url, payloads, options)
            engine.start()

            results = getattr(engine, "results", [])
            chains = getattr(engine, "inferred_chains", [])

            # Generate reports
            reporter = Reporter(options.get("output_dir", "reports"))
            reporter.save_json(results)
            reporter.generate_final_report(results, chains, target_url, {})

            queue.update(
                job_id,
                status=ScanStatus.COMPLETED,
                progress=1.0,
                results=results,
                completed_at=time.time(),
            )
        except Exception as e:
            queue.update(job_id, status=ScanStatus.FAILED, error=str(e))

    @app.post("/scan", response_model=ScanResponse)
    async def start_scan(req: ScanRequest, bg: BackgroundTasks):
        import hunterx

        target_cats = None
        payloads = list(hunterx.load_payloads("payloads", target_cats))

        options = {
            "profile": req.profile,
            "stealth": req.stealth,
            "threads": req.threads,
            "dry_run": req.dry_run,
            "passive_only": req.passive_only,
            "output_dir": req.output_dir,
            "insecure": req.insecure,
            "visual": "off",
        }

        job = queue.create(req.url, req.profile, options)
        bg.add_task(_run_scan_async, job.id, payloads, req.url, options)

        return ScanResponse(job_id=job.id, status=job.status.value, message="Scan started")

    @app.get("/scan/{job_id}")
    async def get_scan(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return {
            "job_id": job.id,
            "status": job.status.value,
            "target": job.target_url,
            "progress": job.progress,
            "results_count": len(job.results),
            "error": job.error,
        }

    @app.get("/scan/{job_id}/results")
    async def get_results(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")
        return {"job_id": job.id, "results": job.results}

    @app.get("/health")
    async def health():
        meta = get_json_metadata()
        return {
            "status": "ok",
            "version": "4.0",
            "copyright": meta["_metadata"]["copyright"],
            "license": meta["_metadata"]["license"],
            "author": meta["_metadata"]["author"],
        }

    @app.get("/info")
    async def info():
        return get_json_metadata()

    @app.get("/jobs")
    async def list_jobs():
        jobs = queue.list_all()
        return [
            {"id": j.id, "target": j.target_url, "status": j.status.value, "progress": j.progress}
            for j in jobs
        ]


def start_api(host: str = "0.0.0.0", port: int = 8443):
    """Start the FastAPI server."""
    if not HAS_FASTAPI:
        logger.error("FastAPI not installed. Run: pip install fastapi uvicorn")
        return
    import uvicorn
    logger.info(f"Starting HunterX API on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
