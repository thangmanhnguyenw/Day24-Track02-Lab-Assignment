# src/api/main.py
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

RAW_DATA_PATH = Path("data/raw/patients_raw.csv")
PROCESSED_DIR = Path("data/processed")


def _load_raw_df() -> pd.DataFrame:
    if not RAW_DATA_PATH.exists():
        raise HTTPException(status_code=404, detail="Raw patient data not found")
    return pd.read_csv(RAW_DATA_PATH)


@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(current_user: dict = Depends(get_current_user)):
    """Trả về 10 bản ghi raw (chỉ admin)."""
    df = _load_raw_df()
    return df.head(10).to_dict(orient="records")


@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(current_user: dict = Depends(get_current_user)):
    """Load raw → anonymize → trả JSON."""
    df = _load_raw_df()
    df_anon = anonymizer.anonymize_dataframe(df)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    df_anon.to_csv(PROCESSED_DIR / "patients_anonymized.csv", index=False)

    return df_anon.head(10).to_dict(orient="records")


@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(current_user: dict = Depends(get_current_user)):
    """Thống kê theo loại bệnh — không chứa PII."""
    df = _load_raw_df()
    counts = df["benh"].value_counts().to_dict()
    return {
        "total_patients": len(df),
        "patients_by_condition": counts,
        "avg_test_result": round(df["ket_qua_xet_nghiem"].mean(), 2),
    }


@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str, current_user: dict = Depends(get_current_user)
):
    """Chỉ admin được xóa."""
    df = _load_raw_df()
    if patient_id not in df["patient_id"].astype(str).values:
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"deleted": True, "patient_id": patient_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
