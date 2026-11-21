"""Load, validate, and filter the cybersecurity traffic dataset."""

from datetime import date
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_FILE = PROJECT_ROOT / "data" / "cybersecurity.csv"

COLUMN_MAPPING = {
    "src_ip": "source_ip",
    "dst_ip": "destination_ip",
    "src_port": "source_port",
    "dst_port": "destination_port",
}

REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "label",
    "attack_type",
}


def prepare_data(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Validate the CSV and standardize it for the dashboard."""
    df = raw_df.copy()

    df.columns = df.columns.str.strip()

    if df.columns.duplicated().any():
        raise ValueError("The CSV contains duplicate column names.")

    missing_columns = REQUIRED_COLUMNS - set(df.columns)

    if missing_columns:
        raise ValueError(
            "The dataset is missing required columns: "
            + ", ".join(sorted(missing_columns))
        )

    if df.empty:
        raise ValueError("The dataset contains no records.")

    df = df.rename(columns=COLUMN_MAPPING)

    # Parse timestamps without silently discarding invalid rows.
    timestamps = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    if timestamps.isna().any():
        invalid_count = int(timestamps.isna().sum())
        raise ValueError(
            f"The dataset contains {invalid_count:,} "
            "missing or invalid timestamps."
        )

    df["timestamp"] = timestamps

    # Validate fields needed for filtering and investigation.
    for column in ["source_ip", "destination_ip", "protocol"]:
        values = df[column].astype("string").str.strip()

        invalid = values.isna() | values.eq("")

        if invalid.any():
            raise ValueError(
                f"Column '{column}' contains "
                f"{int(invalid.sum()):,} missing or empty values."
            )

        df[column] = values

    df["protocol"] = df["protocol"].str.upper()

    # Byte counts must be nonnegative whole numbers.
    for column in ["bytes_sent", "bytes_received"]:
        values = pd.to_numeric(
            df[column],
            errors="coerce",
        )

        invalid = (
            values.isna()
            | values.isin([float("inf"), float("-inf")])
            | values.lt(0)
            | values.mod(1).ne(0)
        )

        if invalid.any():
            raise ValueError(
                f"Column '{column}' contains "
                f"{int(invalid.sum()):,} invalid byte counts."
            )

        df[column] = values.astype("int64")

    # Preserve missing ports but reject malformed nonmissing values.
    for column in ["source_port", "destination_port"]:
        original = df[column]

        values = pd.to_numeric(
            original,
            errors="coerce",
        )

        invalid = (
            (original.notna() & values.isna())
            | (
                values.notna()
                & (
                    ~values.between(0, 65535)
                    | values.mod(1).ne(0)
                )
            )
        )

        if invalid.any():
            raise ValueError(
                f"Column '{column}' contains "
                f"{int(invalid.sum()):,} invalid port values."
            )

        df[column] = values.astype("Int64")

    # This file uses 0 for benign and 1 for attack.
    labels = pd.to_numeric(
        df["label"],
        errors="coerce",
    )

    if not labels.isin([0, 1]).all():
        raise ValueError(
            "The label column must contain only 0 or 1. "
            "Review the dataset before changing the mapping."
        )

    df["label"] = labels.astype("int64")

    df["traffic_label"] = df["label"].map(
        {
            0: "Normal",
            1: "Attack",
        }
    )

    attack_types = (
        df["attack_type"]
        .astype("string")
        .str.strip()
        .str.lower()
        .replace("", pd.NA)
    )

    # Do not silently accept contradictions between the two labels.
    inconsistent = (
        (df["label"].eq(0) & attack_types.ne("benign"))
        | (df["label"].eq(1) & attack_types.eq("benign"))
    ).fillna(False)

    if inconsistent.any():
        raise ValueError(
            "Some label values contradict their attack_type. "
            "Review those records before displaying attack metrics."
        )

    df["attack_type"] = attack_types.fillna("Unspecified")

    # Keep optional fields, including missing URLs, unchanged.
    return (
        df.sort_values("timestamp")
        .reset_index(drop=True)
    )


@st.cache_data(show_spinner="Loading cybersecurity dataset...")
def _read_csv(
    file_path: str,
    modified_ns: int,
    file_size: int,
) -> pd.DataFrame:
    """Cache loading; file metadata helps detect updated CSV files."""
    raw_df = pd.read_csv(file_path)
    return prepare_data(raw_df)


def load_data() -> pd.DataFrame:
    """Load the repository's CSV with clear errors in the interface."""
    if not DATA_FILE.is_file():
        st.error(
            "Dataset not found. Add cybersecurity.csv to the "
            "data folder at the repository root, then commit "
            "and push it to GitHub."
        )
        st.stop()

    try:
        metadata = DATA_FILE.stat()

        return _read_csv(
            str(DATA_FILE),
            metadata.st_mtime_ns,
            metadata.st_size,
        )

    except (
        OSError,
        ValueError,
        OverflowError,
        pd.errors.ParserError,
    ) as error:
        st.error(f"Unable to load the dataset: {error}")
        st.stop()


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