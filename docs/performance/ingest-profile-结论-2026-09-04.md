# ingest 热路径 Profile 取证 — 结论封版(2026-09-04)

> 背景: ingest_batch 并发化(commit 31259ff)在共享单进程部署无线性提速,疑似"共享单线程事件
> 循环 + 无界后台派生"瓶颈。本文件为针对其做的、只读的 CPU/规则微基准取证结论,并就此封版。

## 1. 结论(定稿)
对 600 事件(混合 BRUTE_FORCE/PORT_SCAN/HTTP_ACCESS 等)的同口径拆解,每事件 ingest 总墙钟 ≈
18.9ms(600 → 11.4s ≈ 53 ev/s)。其中两处**显性同步 CPU** 成分实测为:
- `anomaly_detector.analyze`(async 定义但主体为内存基线/统计同步计算, 仅周期 _save_baselines_to_redis):
  600 事件 **0.003s**(≈5µs/事件, <1%) —— **非瓶颈**
- `pySigma` 匹配: 600 事件 **0.42s**(0.71ms/事件, ≈4%) —— 低

⇒ **sigma + anomaly CPU 合计 < 每事件 0.75ms, 不到总耗时 ~4%。** 上一轮关于"单线程 CPU 段是并发不涨
主因"的假设被数据推翻。真正的 ~18ms/事件成本位于其余主路径的 **I/O / 串行等待**(event_store 落库往返、
sliding_window/memory_tree 的 Redis、内存树、索引,以及无界后台派生任务的排队),而非规则/统计计算。

## 2. 对 L1/L2 的含义
- **L2(to_thread 卸载 CPU)在本地图收益 ≈ 0 —— 不做**。两段显性同步 CPU 合计不足每事件 ~0.75ms,
  卸载徒增并发安全复杂度。数据不支持。
- **L1 若要继续,应命中 I/O 串行点**: 需再加默认关闭(可逆)的 phase 探针,把 ~18ms/事件准确拆到
  [event_store 落库 / sliding_window Redis / memory_tree 索引 / 后台派生排队] 各自耗时以定位那个真正的
  串行资源; 对症视角是"批量落库/降 Redis 往返 + 有界后台", 而非把 ingest 热路径整段并发。

## 3. 封版声明
因取证已显示 L2 无收益且该共享单进程瓶颈定位须另行深度拆分(需在生产 DB/Redis 网络口径的 phase 探针),
本次按用户指示在"CPU 非瓶颈"结论处**到此为止**,不再推进 L1 实装或下游优化。本结论留档备查,
若日后要重启优化,起点是第二阶段的可逆 Profile(见 §2),勿重走 CPU 卸载弯路。

## 4. 依据的程序(只读微基准, 非业务逻辑改动)
- 一次性 soc-backend 开发镜像容器(ghcr.io/.../soc-backend:dev, mount 当前 backend 源码):
- sigma: 600 events → sigma_wall_s 0.423, per_event_ms 0.71 (400 hits)
- anomaly: 600 events → anomaly_wall_s 0.003(≈5µs/事件, ≈189k ev/s)
- 探针 `.zzprof.py / .zzan.py` 为临时文件, 已于采集后删除; 运行态保持在默认 Kafka 模式。

