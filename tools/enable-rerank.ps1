# 可选：启用 Infinity cross-encoder。默认栈不拉该镜像。
# 用法（仓库根目录）:
#   powershell -File tools/enable-rerank.ps1
$ErrorActionPreference = "Stop"
$mirror = "docker.m.daocloud.io/michaelf34/infinity:latest"
$local = "michaelf34/infinity:latest"
Write-Host "Pull $mirror ..."
docker pull $mirror
docker tag $mirror $local
Write-Host "Start profile rerank (HF mirror for BGE weights) ..."
$env:HF_ENDPOINT = "https://hf-mirror.com"
docker compose --profile rerank up -d soc-bge-rerank
Write-Host "Set in .env then recreate backend:"
Write-Host "  SHARED_MEMORY_RAG_RERANK_URL=http://soc-bge-rerank:7997/rerank"
Write-Host "Until then RAG already works via BM25+RRF+feature rerank."
