# ── 阶段 1: Maven 构建 ──
FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn package -DskipTests -B

# ── 阶段 2: Flink 运行时 ──
FROM flink:1.18.1-scala_2.12-java11

# 复制构建好的 JAR 到 Flink lib 目录
COPY --from=builder /build/target/flink-jobs-1.0.0.jar /opt/flink/lib/

# 复制 Kafka 连接器及客户端依赖到 Flink lib 目录
# (不打入 fat jar, 由集群统一加载, 避免双类加载器导致的反序列化 ClassCastException)
COPY --from=builder /build/target/kafka-deps/ /opt/flink/lib/

# 复制作业提交脚本
COPY submit-jobs.sh /opt/flink/submit-jobs.sh
RUN chmod +x /opt/flink/submit-jobs.sh
