from fastapi import FastAPI
from pathlib import Path
import json

app = FastAPI()

SWEEPS_DIR = Path("data/sweeps")

@app.post("/sweep")
async def start_sweep():
    from engine import run_all_sweeps
    sweep_id = run_all_sweeps()
    return {"sweep_id": sweep_id, "status": "complete"}

@app.get("/sweep/{sweep_id}")
async def get_sweep(sweep_id: str):
    sweep_dir = SWEEPS_DIR / sweep_id
    if not sweep_dir.exists():
        return {"error": "Sweep not found"}
    
    all_findings = {}
    for json_file in sweep_dir.glob("*.json"):
        if json_file.name == "_metadata.json":
            continue
        with open(json_file) as f:
            all_findings[json_file.stem] = json.load(f)
    
    return all_findings

@app.get("/sweep/latest")
async def get_latest():
    if not SWEEPS_DIR.exists():
        return {"error": "No sweeps found"}
    
    latest = max(SWEEPS_DIR.iterdir(), key=lambda p: p.stat().st_ctime)
    return await get_sweep(latest.name)

@app.get("/")
async def root():
    return {"message": "Security Sweep API", "endpoints": ["POST /sweep", "GET /sweep/{id}", "GET /sweep/latest"]}