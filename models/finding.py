from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class Finding:
    title: str
    severity: str
    message: str
    check: str
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization"""
        return {
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "check": self.check,
            "timestamp": self.timestamp
        }