"""Base agent class and agent communication interfaces."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from rich.console import Console

console = Console()


class BaseAgent(ABC):
    """Abstract base class for all specialized security audit agents."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.logs: List[str] = []

    def log(self, message: str) -> None:
        """Record internal agent log message."""
        entry = f"[{self.name}] {message}"
        self.logs.append(entry)

    @abstractmethod
    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent task on shared state and return updated state."""
        pass

