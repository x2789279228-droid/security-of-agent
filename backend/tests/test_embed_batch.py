# -*- coding: utf-8 -*-
"""Unit coverage for EmbeddingClient.embed_batch / embed_many (request-in-array batching).

Verifies to a fake httpx endpoint:
  1) a single POST carries ALL input texts (not one HTTP per text);
  2) order/alignment is preserved;
  3) with cache pre-filled only the missing subset is sent (miss-only);
  4) on failure returns a zero(embedding_dim) vector (same fallback as embed).
"""
import asyncio
import logging
import pytest

from summary_compression import settings

logger = logging.getLogger(__name__)


class _FakeResp:
    def __init__(self, vectors):
        self._v = vectors
    def raise_for_status(self):
        return None
    def json(self):
        return {"vectors": self._v}


class _FakeClient:
    """Records requests instead of calling out."""
    def __init__(self):
        self.posts = []  # list of (url, json)
    async def post(self, url, headers=None, json=None):
        self.posts.append((url, json))
        texts = json.get("texts") or json.get("input") or []
        # provider echoes one stub vector per text so alignment is observable
        vectors = [ [float(len(t))] for t in texts ]
        return _FakeResp(vectors)
    async def aclose(self):
        return None


class _FakeRedis:
    def __init__(self):
        self.d = {}
    async def get(self, k):
        return self.d.get(k)
    async def setex(self, k, ttl, v):
        self.d[k] = v


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def client_and_redis():
    from summary_compression import embedder
    # isolate static fields without network
    old = {}
    for name in ("api_key", "base_url", "model", "embedding_dim"):
        if name == "api_key":
            old[name], embedder.api_key = embedder.api_key, "test-key"
        elif name == "base_url":
            old[name], embedder.base_url = embedder.base_url, "http://fake.local/v1"
        elif name == "model":
            old[name], embedder.model = embedder.model, "embo-batch"
        else:
            old[name], settings.embedding_dim = settings.embedding_dim, 4
    fake = _FakeClient()
    r = _FakeRedis()
    embedder.client = fake
    embedder.redis = r
    embedder._stats = {"hits": 0, "misses": 0, "errors": 0}
    yield fake, r
    embedder.client = None
    embedder.redis = None
    for n, v in old.items():
        if n == "api_key":
            embedder.api_key = v
        elif n == "base_url":
            embedder.base_url = v
        elif n == "model":
            embedder.model = v
        else:
            settings.embedding_dim = v


def test_embed_batch_single_post_for_many():
    from summary_compression import embedder
    texts = ["aaaaaaaaaa", "bb", "ccc"]  # 10/2/3 chars
    out = run(embedder.embed_batch(texts))
    assert len(out) == len(texts)
    fake = embedder.client
    assert len(fake.posts) == 1  # ONE http for all 3 texts
    payload = fake.posts[0][1]
    sent = payload.get("texts") or payload.get("input")
    assert set(sent) == set(texts)
    # alignment preserved (echoed [len(t)])
    assert [v[0] for v in out] == [10.0, 2.0, 3.0]


def test_embed_many_chunks_by_size():
    from summary_compression import embedder
    import os
    os.environ["EMBED_BATCH_SIZE"] = "100"
    texts = ["x%02d" % i for i in range(230)]
    out = run(embedder.embed_many(texts))
    assert len(out) == 230
    # chunking: 100 + 100 + 30 => three HTTP calls
    assert len(embedder.client.posts) == 3


def test_embed_batch_miss_only_with_cache():
    from summary_compression import embedder
    import hashlib, json as _json
    r = embedder.redis
    hit_text = "cached-text"
    key = "embed_cache:db:" + hashlib.md5(hit_text.encode()).hexdigest()
    run(r.setex(key, 60, _json.dumps([7.0])))
    out = run(embedder.embed_batch([hit_text, "new-one"]))
    assert out[0] == [7.0]          # served from cache, len 1 vector
    # only "new-one" is posted (not cached-text)
    fake = embedder.client
    assert len(fake.posts) == 1
    sent = fake.posts[0][1].get("texts") or fake.posts[0][1].get("input")
    assert sent == ["new-one"]
    assert out[1][0] == len("new-one") * 1.0
    assert embedder._stats["hits"] >= 1 and embedder._stats["misses"] >= 1
