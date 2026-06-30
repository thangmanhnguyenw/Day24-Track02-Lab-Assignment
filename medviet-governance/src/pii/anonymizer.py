# src/pii/anonymizer.py
import random
import pandas as pd
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker
from .detector import build_vietnamese_analyzer, detect_pii, _normalize_pii_text

fake = Faker("vi_VN")


def _fake_cccd() -> str:
    return str(random.randint(0, 9)) + "".join(str(random.randint(0, 9)) for _ in range(11))


def _fake_phone() -> str:
    return f"0{random.choice([3, 5, 7, 8, 9])}" + "".join(
        str(random.randint(0, 9)) for _ in range(8)
    )


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def _build_operators(self, strategy: str) -> dict:
        if strategy == "replace":
            return {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace", {"new_value": _fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": _fake_phone()}),
            }
        if strategy == "mask":
            mask_cfg = {"masking_char": "*", "chars_to_mask": 100, "from_end": False}
            return {
                "PERSON": OperatorConfig("mask", mask_cfg),
                "EMAIL_ADDRESS": OperatorConfig("mask", mask_cfg),
                "VN_CCCD": OperatorConfig("mask", mask_cfg),
                "VN_PHONE": OperatorConfig("mask", mask_cfg),
            }
        if strategy == "hash":
            hash_cfg = {"hash_type": "sha256"}
            return {
                "PERSON": OperatorConfig("hash", hash_cfg),
                "EMAIL_ADDRESS": OperatorConfig("hash", hash_cfg),
                "VN_CCCD": OperatorConfig("hash", hash_cfg),
                "VN_PHONE": OperatorConfig("hash", hash_cfg),
            }
        return {}

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """Anonymize text với strategy: replace | mask | hash."""
        if not text or not str(text).strip():
            return text

        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        operators = self._build_operators(strategy)
        anonymized = self.anonymizer.anonymize(
            text=str(text),
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Anonymize toàn bộ DataFrame, giữ nguyên cột clinical & patient_id."""
        df_anon = df.copy()

        text_columns = ["ho_ten", "dia_chi", "email", "bac_si_phu_trach"]
        for col in text_columns:
            if col in df_anon.columns:
                df_anon[col] = df_anon[col].apply(
                    lambda x: self.anonymize_text(str(x), strategy="replace")
                )

        if "cccd" in df_anon.columns:
            df_anon["cccd"] = [_fake_cccd() for _ in range(len(df_anon))]

        if "so_dien_thoai" in df_anon.columns:
            df_anon["so_dien_thoai"] = [_fake_phone() for _ in range(len(df_anon))]

        if "ngay_sinh" in df_anon.columns:
            df_anon["ngay_sinh"] = df_anon["ngay_sinh"].apply(
                lambda x: x.split("/")[-1] if isinstance(x, str) and "/" in x else x
            )

        return df_anon

    def calculate_detection_rate(
        self, original_df: pd.DataFrame, pii_columns: list
    ) -> float:
        """Tính % ô PII được detect thành công (mục tiêu > 95%)."""
        total = 0
        detected = 0

        for col in pii_columns:
            if col not in original_df.columns:
                continue
            for value in original_df[col].astype(str):
                if not value.strip():
                    continue
                total += 1
                cell = _normalize_pii_text(value) if col in ("cccd", "so_dien_thoai") else value
                results = detect_pii(cell, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
