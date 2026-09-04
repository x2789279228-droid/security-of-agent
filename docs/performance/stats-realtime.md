# Monitor 统计卡实时化 — 实现记录
**日期**: 2026-09-04 | commit: 6ff43ed(后端) + 前端 Monitor.tsx 间隔
**范围**: Monitor 主统计卡: 安全事件 / 待处理 / 审计已完成(近似实时) + 低频 COUNT 校准(默认 8s).

## 为什么
Monitor 统计卡此前由 `GET /api/stats`(routers/chat.py)支撑, 每次(事件推送后≥5s节点流)跑一次多个全表
`SELECT COUNT`;后台为防高压用 5s 进程内 TTL 缓存 + 合并成单条标量子查询, 使卡片在事件涌入时滞后、
且不断全表 count 有 DB 开销。用户要求该数能实时更新。

## 方案(近似值 + 后端计数器 + 低频校准, 用户确认)
- 新 `backend/stats_counter.py`: Redis keys `soc-stats:{total,done,pending}`。
  - `inc_insert()`(新增行: total+1/pending+1)
  - `inc_analyzed_done()`(审计完成: done+1/pending-1)
  - `snapshot()` / `reconcile(abs)`(写绝对真值)
  - Redis 不可用 → 所有 helper no-op + `/stats` 自动回退真 COUNT(不破坏现有语义)
  开关 env `SHARED_MEMORY_STATS_COUNTER_ENABLED`(默认 on)。
- 接入唯一的真实新增低点: `event_store.store` 在(非幂等命中/非 IntegrityError 回滚)成功后 `inc_insert()`。
  审记完成 3 sinks(log_ingestion `db_evt.analyzed=True`) → `inc_analyzed_done()`。(pending/completed 多写路径
  会有窗口内近似漂移,交由校准吸收。)
- `/stats`(chat.py)改造:
  - fresh 窗口(默认 8s,env `SHARED_MEMORY_STATS_RECONCILE_EVERY_S`)内**从 Redis 秒回**并在最近一次全量
    reconcile 的 payload 上覆写 security_events/pending/audit 三项(保持 tree/redis 等不闪 0)。
  - 非 fresh → 一次合并 COUNT+原子 reconcile 回真值并缓存近期全量 payload(并发用 asyncio.Lock 防止同拍多跑)。
  - payload 契约不变 → 前端无需结构改动。
- 前端 Monitor.tsx: `STATS_MIN_INTERVAL` 5s→2s(因 /api/stats 已在 fresh 窗口内秒回, 缩短不至打库)。

## 实测(真实Kafka权威队列 + Redis, ioctl postgres)
- initial(累计): security_events=24853, pending=0, completed=24853
- 经网关推 300 → 3s 后(队列部分消化): security_events=25005(+152), pending=33 → **Redis 计数即时上跳, 非 COUNT**
- +8s(触发 reconcile 真 COUNT): security_events=25153, completed=25153, pending=0, tree=29985(**收敛精确**)

## 回归
- 相关 tests(挂当前源码/sqlite回退路径): 38 passed(import/log 兼容 event_store/log_ingestion 新 hooks)。

## 边界/风险(默认合理)
- 数值在两次 reconcile 间允许近似(删除/回滚/审记多写漂移由 ≤8s 校准吸收)——用户已认可近似口径。
- 若 Redis 短暂不可用, increment no-op + `/stats` 回到真 COUNT 路径(会像改造前那样慢但不错)。
- 多副本:计数以共享 Redis 为准 + 校准覆盖, 不放大误差。
