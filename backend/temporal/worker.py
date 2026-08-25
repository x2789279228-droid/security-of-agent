"""
temporal.worker — Temporal Worker(独立常驻进程)

注册 AuditPipelineWorkflow + 各 Activity, 消费 temporal.task_queue。
独立进程运行:
  docker compose up -d temporal-worker  或  python -m temporal.worker
"""
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("temporal-worker")


async def run_worker():
    from config import settings
    from temporalio.client import Client
    from temporalio.worker import Worker

    # 初始化 OTel(让 activity 内 pipeline_tracer.span 导出到 collector → Tempo/Jaeger)
    try:
        from otel_setup import setup_otel
        setup_otel()
    except Exception as e:
        logging.getLogger(__name__).warning(f"worker otel init failed: {e}")

    from temporal.workflows import AuditPipelineWorkflow
    from temporal.activities import audit_round, save_result, trigger_response, cad_verify

    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[AuditPipelineWorkflow],
        activities=[audit_round, save_result, trigger_response, cad_verify],
    )
    logger.info(f"Temporal worker starting: {settings.temporal_host} queue={settings.temporal_task_queue}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
