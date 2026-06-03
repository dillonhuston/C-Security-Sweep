import json
import os
from datetime import datetime
from pathlib import Path

def run_all_sweeps():
    # make folder with timestamp
    now = datetime.now()
    ts = f"{now.year}{now.month:02d}{now.day:02d}_{now.hour:02d}{now.minute:02d}{now.second:02d}"
    sweep_dir = Path(f"data/sweeps/{ts}")
    sweep_dir.mkdir(parents=True, exist_ok=True)

    # import all the shit
    from tasks.check_open_ports import open_ports
    from tasks.check_running_processes import running_processes
    from tasks.scheduled_tasks import scheduled_tasks
    from tasks.world_writable import world_writable
    from tasks.failed_logins import failed_logins
    from tasks.firewall import firewall

    # dict of stuff to run
    tasks = {
        "open_ports": open_ports,
        "running_processes": running_processes,
        "scheduled_tasks": scheduled_tasks,
        "world_writable": world_writable,
        "failed_logins": failed_logins,
        "firewall": firewall,
    }

    results = {}
    errors = {}

    print(f"\n>>> STARTING SWEEP {ts}")
    print("="*50)

    # loop through tasks
    for name, func in tasks.items():
        print(f"[*] checking {name}...")
        try:
            data = func()
            results[name] = data
            print(f"    found {len(data)} issues")
        except Exception as e:
            errors[name] = str(e)
            results[name] = []
            print(f"    FAILED - {e}")

    print("="*50)
    print("[DONE]")

    # save everything to json files
    for name, data in results.items():
        fpath = sweep_dir / f"{name}.json"
        with open(fpath, "w") as f:
            json.dump(data, f, indent=2)

    # save metadata
    meta = {
        "ts": ts,
        "sweep_id": ts,
        "done": list(results.keys()),
        "failed": list(errors.keys()),
        "machine": os.environ.get("COMPUTERNAME", "unknown")
    }
    with open(sweep_dir / "_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    return ts, sweep_dir

# run it
if __name__ == "__main__":
    sweep_id, sweep_dir = run_all_sweeps()
    print(f"\n> saved to {sweep_dir}")
    print(f"> id: {sweep_id}")