"""临时验证: log_ingestion 归一化 method/status 字段 (验证后删除)"""
import pytest

from log_ingestion import log_ingestor as log_ingestion


def test_normalize_method_status():
    # 顶层 method/status
    ev1 = {"url": "/api/users?id=x", "eventType": "REQUEST", "srcIp": "1.2.3.4",
           "message": "req", "severity": "medium", "method": "GET", "status": 200}
    n1 = log_ingestion._normalize_fields(ev1)
    assert n1.get("method") == "GET"
    assert n1.get("status") == 200


def test_normalize_rawdata_fallback():
    # rawData 兜底
    ev2 = {"message": "req", "severity": "medium", "eventType": "REQUEST",
           "rawData": {"method": "POST", "statusCode": 500, "requestUrl": "/q?=<script>x"}}
    n2 = log_ingestion._normalize_fields(ev2)
    assert n2.get("method") == "POST"
    assert n2.get("status") == 500
    assert n2.get("url") == "/q?=<script>x"


def test_normalize_no_http_fields():
    ev3 = {"url": "/home", "eventType": "REQUEST", "message": "x", "severity": "info"}
    n3 = log_ingestion._normalize_fields(ev3)
    assert n3.get("method", None) in (None, "")
    assert n3.get("status", None) in (None, "")
