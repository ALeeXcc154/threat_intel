import uuid
import tempfile
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, List
import anyio

from threat_intel import ThreatIntelProcessor


def create_app():
    app = FastAPI()

    OUTPUT_DIR = Path(tempfile.gettempdir()) / "threat_intel_output"
    OUTPUT_DIR.mkdir(exist_ok=True)

    class AnalyzeRequest(BaseModel):
        url: HttpUrl

    class ReportRequest(BaseModel):
        results: List[Dict] = Field(..., min_length=1)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return Path(__file__).parent.joinpath("index.html").read_text(encoding="utf-8")

    @app.post("/api/v1/threat-intelligence/analyze")
    async def analyze(request: AnalyzeRequest):
        url = str(request.url)
        processor = ThreatIntelProcessor()
        success, entries, error = await anyio.to_thread.run_sync(processor.process_url, url)

        if success:
            return {
                "success": True,
                "entries": entries,
                "title": entries[0].get("main_title", "威胁情报") if entries else "威胁情报"
            }
        return {"success": False, "error": error}

    @app.post("/api/v1/threat-intelligence/report")
    async def report(request: ReportRequest):
        processor = ThreatIntelProcessor()
        task_id = str(uuid.uuid4())
        output_path = OUTPUT_DIR / f"threat_intel_{task_id}.docx"

        urls = [r.get("url") for r in request.results if r.get("url")]
        success, messages = await anyio.to_thread.run_sync(
            processor.generate_document, urls, str(output_path)
        )

        if success:
            return FileResponse(
                output_path,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                filename=f"威胁情报_{task_id}.docx"
            )
        raise HTTPException(status_code=500, detail="文档生成失败")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
