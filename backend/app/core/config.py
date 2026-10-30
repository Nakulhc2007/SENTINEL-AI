from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "SENTINEL-AI"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"
    MODEL_PATH: str = "../models/sentinel_model.pkl"
    MODEL_META_PATH: str = "../models/sentinel_model_meta.pkl"
    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"
    NORMALIZED_DATA_DIR: str = "../data/processed/normalized"

    model_config = {"env_file": ".env"}


settings = Settings()
