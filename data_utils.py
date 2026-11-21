"""Data generation, filtering, and formatting for the traffic dashboard."""

from datetime import date, datetime, timedelta
import random

import pandas as pd
import streamlit as st


@st.cache_data
def load_demo_data() -> pd.DataFrame:
    """Generate reproducible sample network-traffic records."""
    rng = random.Random(42)
    start = datetime(2026, 1, 1)
    protocols = ["TCP", "UDP", "ICMP"]
    records = []

    for _ in range(1500):
        protocol = rng.choices(
            protocols,
            weights=[65, 30, 5],
            k=1,
        )[0]

        # Use missing port values for generated ICMP records.
        source_port = (
            rng.randint(1024, 65535)
            if protocol != "ICMP"
            else None
        )

        destination_port = (
            rng.choice([22, 53, 80, 123, 443, 3389, 8080])
            if protocol != "ICMP"
            else None
        )

        records.append(
            {
                "timestamp": start
                + timedelta(
                    seconds=rng.randrange(30 * 24 * 60 * 60)
                ),
                "source_ip": (
                    f"192.168.1.{rng.randint(1, 50)}"
                ),
                "destination_ip": (
                    f"10.0.0.{rng.randint(1, 30)}"
                ),
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol,
                "bytes_sent": rng.randint(100, 100_000),
                "bytes_received": rng.randint(100, 250_000),
            }
        )

    df = pd.DataFrame(records)

    df["source_port"] = df["source_port"].astype("Int64")
    df["destination_port"] = df["destination_port"].astype("Int64")

    return (
        df.sort_values("timestamp")
        .reset_index(drop=True)
    )


def filter_traffic(
    df: pd.DataFrame,
    protocols: list[str],
    start_date: date,
    end_date: date,
) -> pd.DataFrame:
    """Return records matching protocols and inclusive calendar dates."""
    dates = df["timestamp"].dt.date

    mask = (
        df["protocol"].isin(protocols)
        & (dates >= start_date)
        & (dates <= end_date)
    )

    return df.loc[mask].copy()


def format_bytes(value: float) -> str:
    """Format a byte count using binary units."""
    size = float(value)

    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:,.1f} {unit}"

        size /= 1024

    return f"{size:,.1f} TiB"