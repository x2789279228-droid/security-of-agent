# ── 阶段 1: Maven 构建 ──
FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B

# 拉取 Flink 运行时扩展 jar (RocksDB 状态后端 + Prometheus Reporter)
# 放入 /opt/flink/lib 由集群类加载器统一加载 (生产级: 大状态 + 指标可观测)
RUN mvn dependency:copy \
        -Dartifact=org.apache.flink:flink-statebackend-rocksdb:1.19.3 \
        -DoutputDirectory=/build/extra-lib \
        -Dtransitive=false -B
RUN mvn dependency:copy \
        -Dartifact=org.apache.flink:flink-metrics-prometheus:1.19.3 \
        -DoutputDirectory=/build/extra-lib \
        -Dtransitive=false -B

COPY src ./src
RUN mvn package -DskipTests -B

# ── 阶段 2: Flink 运行时 ──
FROM flink:1.19.3-scala_2.12-java11

# 复制构建好的 JAR 到 Flink lib 目录
COPY --from=builder /build/target/flink-jobs-1.0.0.jar /opt/flink/lib/

# 复制 Kafka 连接器及客户端依赖到 Flink lib 目录
# (不打入 fat jar, 由集群统一加载, 避免双类加载器导致的反序列化 ClassCastException)
COPY --from=builder /build/target/kafka-deps/ /opt/flink/lib/

# 复制 RocksDB 状态后端 + Prometheus 指标扩展
COPY --from=builder /build/extra-lib/ /opt/flink/lib/

# 复制作业提交脚本
COPY submit-jobs.sh /opt/flink/submit-jobs.sh
RUN chmod +x /opt/flink/submit-jobs.sh
