# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE", "VN_NAME"]


def _normalize_pii_text(text: str) -> str:
    """Chuẩn hóa CCCD/SĐT khi CSV đọc mất số 0 đầu."""
    s = str(text).strip()
    if s.isdigit():
        if len(s) == 11:
            return s.zfill(12)
        if len(s) == 9 and s[0] in "35789":
            return "0" + s
    return s


def _make_pattern_recognizer(entity: str, patterns: list, context: list | None = None):
    """Tạo recognizer hỗ trợ cả vi và en."""
    kwargs = {"supported_entity": entity, "patterns": patterns}
    if context:
        kwargs["context"] = context
    rec_vi = PatternRecognizer(supported_language="vi", **kwargs)
    rec_en = PatternRecognizer(supported_language="en", **kwargs)
    return rec_vi, rec_en


def _create_nlp_engine():
    """Tạo NLP engine — ưu tiên model VN, fallback en_core_web_sm."""
    import spacy

    for model_name, lang in (
        ("vi_core_news_lg", "vi"),
        ("vi_core_news_sm", "vi"),
        ("en_core_web_sm", "en"),
    ):
        try:
            spacy.load(model_name)
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": lang, "model_name": model_name}],
                }
            )
            return provider.create_engine(), lang
        except OSError:
            continue

    raise OSError(
        "Không tìm thấy model spaCy. Chạy: python -m spacy download en_core_web_sm"
    )


def build_vietnamese_analyzer() -> AnalyzerEngine:
    """Xây dựng AnalyzerEngine với các recognizer tùy chỉnh cho VN."""

    cccd_pattern = Pattern(
        name="cccd_pattern",
        regex=r"\b\d{12}\b",
        score=0.9,
    )
    cccd_recognizer_vi, cccd_recognizer_en = _make_pattern_recognizer(
        "VN_CCCD",
        [cccd_pattern],
        context=["cccd", "căn cước", "chứng minh", "cmnd"],
    )

    phone_patterns = [
        Pattern(name="vn_phone", regex=r"\b0[35789]\d{8}\b", score=0.85),
        Pattern(name="vn_phone_no_zero", regex=r"\b[35789]\d{8}\b", score=0.8),
    ]
    phone_recognizer_vi, phone_recognizer_en = _make_pattern_recognizer(
        "VN_PHONE",
        phone_patterns,
        context=["điện thoại", "sdt", "phone", "liên hệ"],
    )

    email_pattern = Pattern(
        name="email_pattern",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        score=0.9,
    )
    email_recognizer_vi, email_recognizer_en = _make_pattern_recognizer(
        "EMAIL_ADDRESS", [email_pattern]
    )

    vn_name_pattern = Pattern(
        name="vn_name_pattern",
        regex=(
            r"^[A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ"
            r"a-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ"
            r"]+(?:\s+[A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ"
            r"a-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]+){1,5}$"
        ),
        score=0.8,
    )
    vn_name_recognizer_vi, vn_name_recognizer_en = _make_pattern_recognizer(
        "VN_NAME", [vn_name_pattern]
    )

    nlp_engine, nlp_lang = _create_nlp_engine()
    if nlp_lang == "en" and "vi" not in nlp_engine.nlp:
        nlp_engine.nlp["vi"] = nlp_engine.nlp["en"]

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    for rec in (
        cccd_recognizer_vi,
        cccd_recognizer_en,
        phone_recognizer_vi,
        phone_recognizer_en,
        email_recognizer_vi,
        email_recognizer_en,
        vn_name_recognizer_vi,
        vn_name_recognizer_en,
    ):
        analyzer.registry.add_recognizer(rec)

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect PII trong text tiếng Việt."""
    if not text or not str(text).strip():
        return []

    normalized = _normalize_pii_text(text)
    results = []

    for lang in ("vi", "en"):
        try:
            results = analyzer.analyze(
                text=normalized,
                language=lang,
                entities=PII_ENTITIES,
            )
            if results:
                break
        except (ValueError, KeyError):
            continue

    for r in results:
        if r.entity_type == "VN_NAME":
            r.entity_type = "PERSON"

    return results
