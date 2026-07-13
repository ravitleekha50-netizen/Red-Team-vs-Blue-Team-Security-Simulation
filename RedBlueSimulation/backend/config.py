import os

class Config:
    SECRET_KEY = "super_secret_session_key_for_simulation"
    DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "database", "simulation.db"))
    SECURITY_ENABLED = False
