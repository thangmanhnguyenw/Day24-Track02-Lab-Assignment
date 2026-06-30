# src/quality/validation.py
import re
from pathlib import Path

import pandas as pd
import great_expectations as gx
from great_expectations.core.expectation_suite import ExpectationSuite

RAW_DATA_PATH = Path("data/raw/patients_raw.csv")
VALID_CONDITIONS = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
EMAIL_REGEX = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"


def build_patient_expectation_suite() -> ExpectationSuite:
    """Tạo expectation suite cho patient data."""
    context = gx.get_context()
    suite_name = "patient_data_suite"
    try:
        suite = context.add_expectation_suite(suite_name)
    except Exception:
        suite = context.get_expectation_suite(suite_name)

    df = pd.read_csv(RAW_DATA_PATH)
    validator = context.sources.pandas_default.read_dataframe(df)

    validator.expect_column_values_to_not_be_null("patient_id")
    validator.expect_column_value_lengths_to_equal(column="cccd", value=12)
    validator.expect_column_values_to_be_between(
        column="ket_qua_xet_nghiem", min_value=0, max_value=50
    )
    validator.expect_column_values_to_be_in_set(
        column="benh", value_set=VALID_CONDITIONS
    )
    validator.expect_column_values_to_match_regex(column="email", regex=EMAIL_REGEX)
    validator.expect_column_values_to_be_unique(column="patient_id")

    validator.save_expectation_suite()
    return suite


def validate_anonymized_data(filepath: str) -> dict:
    """Validate anonymized data sau pipeline."""
    df = pd.read_csv(filepath)
    original_df = pd.read_csv(RAW_DATA_PATH)

    results = {
        "success": True,
        "failed_checks": [],
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns),
        },
    }

    original_cccds = set(original_df["cccd"].astype(str))
    leaked = df["cccd"].astype(str).isin(original_cccds).sum()
    if leaked > 0:
        results["success"] = False
        results["failed_checks"].append(
            f"Found {leaked} original CCCD values still present after anonymization"
        )

    important_cols = ["patient_id", "benh", "ket_qua_xet_nghiem"]
    for col in important_cols:
        if col in df.columns and df[col].isnull().any():
            results["success"] = False
            results["failed_checks"].append(f"Null values found in column '{col}'")

    if len(df) != len(original_df):
        results["success"] = False
        results["failed_checks"].append(
            f"Row count mismatch: anonymized={len(df)}, original={len(original_df)}"
        )

    return results
