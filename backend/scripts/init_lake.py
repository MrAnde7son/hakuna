#!/usr/bin/env python3
"""Bootstrap the Iceberg lake — creates namespace and events table if missing.

Usage:
    cd backend
    python scripts/init_lake.py

Idempotent: safe to run multiple times.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def init_lake():
    try:
        from pyiceberg.catalog import load_catalog
        from pyiceberg.schema import Schema
        from pyiceberg.types import (
            NestedField, StringType, LongType, TimestamptzType, DateType, BooleanType,
        )
        from pyiceberg.partitioning import PartitionSpec, PartitionField
        from pyiceberg.transforms import BucketTransform, DayTransform
        from pyiceberg.table.sorting import SortOrder, SortField
    except ImportError:
        logger.error("pyiceberg not installed. Run: pip install 'pyiceberg[duckdb,sql-postgres,s3fs]==0.9.1'")
        sys.exit(1)

    from services.event_store.lake_iceberg import _get_lake_config, ICEBERG_NAMESPACE, ICEBERG_TABLE

    config = _get_lake_config()
    logger.info("Connecting to Iceberg catalog (warehouse=%s)", config.get("warehouse"))

    catalog = load_catalog("hakuna_lake", **config)

    # Create namespace if missing
    namespaces = [ns[0] if isinstance(ns, tuple) else ns for ns in catalog.list_namespaces()]
    if ICEBERG_NAMESPACE not in namespaces:
        catalog.create_namespace(ICEBERG_NAMESPACE)
        logger.info("Created namespace: %s", ICEBERG_NAMESPACE)
    else:
        logger.info("Namespace already exists: %s", ICEBERG_NAMESPACE)

    # Check if table exists
    tables = catalog.list_tables(ICEBERG_NAMESPACE)
    table_names = [t[1] if isinstance(t, tuple) else t for t in tables]
    if "events" in table_names:
        logger.info("Table already exists: %s", ICEBERG_TABLE)
        return

    # Define schema matching SIEMEvent
    schema = Schema(
        NestedField(field_id=1, name="id", field_type=StringType(), required=True),
        NestedField(field_id=2, name="org_id", field_type=LongType(), required=True),
        NestedField(field_id=3, name="event_time", field_type=TimestamptzType(), required=True),
        NestedField(field_id=4, name="ingested_at", field_type=TimestamptzType(), required=True),
        NestedField(field_id=5, name="source_system", field_type=StringType(), required=True),
        NestedField(field_id=6, name="source_id", field_type=StringType(), required=False),
        NestedField(field_id=7, name="event_type", field_type=StringType(), required=True),
        NestedField(field_id=8, name="event_category", field_type=StringType(), required=False),
        NestedField(field_id=9, name="severity", field_type=StringType(), required=True),
        NestedField(field_id=10, name="action", field_type=StringType(), required=False),
        NestedField(field_id=11, name="outcome", field_type=StringType(), required=False),
        NestedField(field_id=12, name="asset_id", field_type=LongType(), required=False),
        NestedField(field_id=13, name="user_name", field_type=StringType(), required=False),
        NestedField(field_id=14, name="source_ip", field_type=StringType(), required=False),
        NestedField(field_id=15, name="dest_ip", field_type=StringType(), required=False),
        NestedField(field_id=16, name="host_name", field_type=StringType(), required=False),
        NestedField(field_id=17, name="message", field_type=StringType(), required=False),
        NestedField(field_id=18, name="raw_json", field_type=StringType(), required=False),
        NestedField(field_id=19, name="normalized_json", field_type=StringType(), required=False),
        NestedField(field_id=20, name="dedup_hash", field_type=StringType(), required=True),
        NestedField(field_id=21, name="integration_id", field_type=StringType(), required=False),
        NestedField(field_id=22, name="event_date", field_type=DateType(), required=True),
    )

    # Partition by bucket(org_id, 16) + days(event_time)
    partition_spec = PartitionSpec(
        PartitionField(source_id=2, field_id=1000, transform=BucketTransform(num_buckets=16), name="org_id_bucket"),
        PartitionField(source_id=3, field_id=1001, transform=DayTransform(), name="event_time_day"),
    )

    # Sort by event_time descending
    sort_order = SortOrder(
        SortField(source_id=3, transform=None, null_order="nulls-last"),
    )

    catalog.create_table(
        identifier=ICEBERG_TABLE,
        schema=schema,
        partition_spec=partition_spec,
        sort_order=sort_order,
    )
    logger.info("Created Iceberg table: %s (partitioned by org_id bucket + event_time day)", ICEBERG_TABLE)


if __name__ == "__main__":
    init_lake()
