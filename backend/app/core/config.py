import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
DB_PATH = BASE_DIR / "cybersentinel.db"

PROJECT_NAME = "CyberSentinel"
VERSION = "1.0.0"
STUDENT_NAME = "Parth Pawar & Aryaman V Saboo"
STUDENT_ROLL = "2024SEPVUGP0021 & 2024SEPVUGP0039"
COURSE_NAME = "Foundation of Cyber Security (STCS225)"
UNIVERSITY = "Vijaybhoomi University - VSST"

SCAN_TIMEOUT = 12.0  # seconds
USER_AGENT = "CyberSentinel-SecurityAuditor/1.0 (Ethical Defensive Assessment; Parth-Pawar-2024SEPVUGP0021-Aryaman-Saboo-2024SEPVUGP0039)"

# Safe mock testing server ports/paths
MOCK_SERVER_HOST = "127.0.0.1"
MOCK_SERVER_PORT = 8000
