import os
import json
import logging
import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, window, expr, pandas_udf
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType, TimestampType
from fusion.anomaly_model import load_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("StreamProcessor")

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
INPUT_TOPIC = "darip-signals"
OUTPUT_TOPIC = "darip-exposures"

# Load the model at the driver node
try:
    clf_model = load_model()
except Exception as e:
    logger.error(f"Could not load ML model: {e}")
    clf_model = None

# Define the schema for incoming signals
# We assume signals are JSON containing asset_id, timestamp, and some metrics
signal_schema = StructType([
    StructField("asset_id", StringType(), True),
    StructField("timestamp", TimestampType(), True),
    StructField("connection_count", IntegerType(), True),
    StructField("cve_criticality", DoubleType(), True),
    StructField("unique_ips", IntegerType(), True),
    StructField("centrality", DoubleType(), True)
])

# Output schema for pandas UDF
@pandas_udf("double")
def predict_anomaly(avg_connection_rate: pd.Series, cve_criticality_sum: pd.Series, unique_ips_contacted: pd.Series, degree_centrality: pd.Series) -> pd.Series:
    """
    Pandas UDF to apply the Isolation Forest model on the aggregated temporal embeddings.
    Returns 1 for anomaly, -1 for normal (Isolation Forest convention).
    We map to 1.0 (Anomaly) and 0.0 (Normal) for simplicity.
    """
    if clf_model is None:
        return pd.Series([0.0] * len(avg_connection_rate))
    
    # Create DataFrame from series
    df = pd.DataFrame({
        'avg_connection_rate': avg_connection_rate,
        'cve_criticality_sum': cve_criticality_sum,
        'unique_ips_contacted': unique_ips_contacted,
        'degree_centrality': degree_centrality
    })
    
    # Predict (-1 is anomaly, 1 is inlier)
    preds = clf_model.predict(df)
    
    # Map to 1.0 (anomaly) and 0.0 (normal)
    mapped_preds = [1.0 if p == -1 else 0.0 for p in preds]
    return pd.Series(mapped_preds)

def start_stream():
    """
    Start the PySpark Structured Streaming application.
    """
    logger.info(f"Starting Spark Streaming connected to Kafka: {KAFKA_BROKER}")
    
    spark = SparkSession.builder \
        .appName("DARIP_StreamProcessor") \
        .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0") \
        .getOrCreate()
        
    spark.sparkContext.setLogLevel("WARN")

    # 1. Read from Kafka
    df = spark \
        .readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("subscribe", INPUT_TOPIC) \
        .option("startingOffsets", "latest") \
        .load()

    # 2. Parse JSON
    parsed_df = df.selectExpr("CAST(value AS STRING)") \
        .select(from_json(col("value"), signal_schema).alias("data")) \
        .select("data.*")

    # 3. Complex Event Processing (CEP) / Windowing
    # Aggregate over a 5-minute sliding window, sliding every 1 minute
    windowed_df = parsed_df \
        .withWatermark("timestamp", "10 minutes") \
        .groupBy(
            window(col("timestamp"), "5 minutes", "1 minute"),
            col("asset_id")
        ) \
        .agg(
            expr("avg(connection_count)").alias("avg_connection_rate"),
            expr("sum(cve_criticality)").alias("cve_criticality_sum"),
            expr("sum(unique_ips)").alias("unique_ips_contacted"),
            expr("avg(centrality)").alias("degree_centrality")
        )

    # 4. Anomaly Detection using Pandas UDF
    scored_df = windowed_df.withColumn(
        "is_anomaly",
        predict_anomaly(
            col("avg_connection_rate"),
            col("cve_criticality_sum"),
            col("unique_ips_contacted"),
            col("degree_centrality")
        )
    )

    # 5. Filter only anomalies
    exposures_df = scored_df.filter(col("is_anomaly") == 1.0)

    # 6. Format output for Kafka
    output_df = exposures_df.selectExpr(
        "asset_id AS key",
        "to_json(struct(*)) AS value"
    )

    # 7. Write to Kafka
    query = output_df \
        .writeStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", KAFKA_BROKER) \
        .option("topic", OUTPUT_TOPIC) \
        .option("checkpointLocation", "/tmp/spark_checkpoint") \
        .outputMode("append") \
        .start()

    logger.info("Stream processor is running...")
    query.awaitTermination()

if __name__ == "__main__":
    start_stream()
