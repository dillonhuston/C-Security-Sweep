import subprocess

def run_cmd(cmd: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""  # Return empty on timeout, don't raise
    except Exception:
        return ""