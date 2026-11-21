from datetime import datetime, timedelta
import random

import pandas as pd
import streamlit as st


# ---------- Page setup ----------

st.set_page_config(
    page_title="Cybersecurity Traffic Explorer",
    page_icon=None,
    layout="wide",
)


# ---------- Data ----------

@st.cache_data
def load_demo_data() -> pd.DataFrame:
    """Generate reproducible sample traffic for the dashboard mockup."""
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

        # ICMP does not use TCP/UDP port numbers.
        source_port = (
            rng.randint(1024, 65535) if protocol != "ICMP" else None
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
                "source_ip": f"192.168.1.{rng.randint(1, 50)}",
                "destination_ip": f"10.0.0.{rng.randint(1, 30)}",
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

    return df.sort_values("timestamp").reset_index(drop=True)


def filter_traffic(
    df: pd.DataFrame,
    protocols: list[str],
    start_date,
    end_date,
) -> pd.DataFrame:
    """Filter records by protocol and inclusive calendar dates."""
    dates = df["timestamp"].dt.date

    mask = (
        df["protocol"].isin(protocols)
        & (dates >= start_date)
        & (dates <= end_date)
    )

    return df.loc[mask].copy()


def format_bytes(value: float) -> str:
    """Format byte counts using binary units."""
    size = float(value)

    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:,.1f} {unit}"
        size /= 1024

    return f"{size:,.1f} TiB"


# ---------- Interface components ----------

def render_metrics(df: pd.DataFrame) -> None:
    """Show summary values for the current selection."""
    records_col, sent_col, received_col, sources_col = st.columns(4)

    records_col.metric("Matching records", f"{len(df):,}")
    sent_col.metric("Bytes sent", format_bytes(df["bytes_sent"].sum()))
    received_col.metric(
        "Bytes received",
        format_bytes(df["bytes_received"].sum()),
    )
    sources_col.metric(
        "Unique source IPs",
        f"{df['source_ip'].nunique():,}",
    )


def render_charts(df: pd.DataFrame) -> None:
    """Render activity, protocol, and destination-port charts."""
    st.subheader("Network activity over time")
    st.caption("Each point shows the number of records for one day.")

    daily_activity = (
        df.set_index("timestamp")
        .resample("D")
        .size()
        .rename("Records")
        .to_frame()
    )

    st.line_chart(daily_activity)

    protocol_col, port_col = st.columns(2)

    with protocol_col:
        st.subheader("Protocol distribution")

        protocol_counts = (
            df["protocol"]
            .value_counts()
            .rename_axis("Protocol")
            .rename("Records")
            .to_frame()
        )

        st.bar_chart(protocol_counts)

    with port_col:
        st.subheader("Top destination ports")

        port_counts = (
            df["destination_port"]
            .dropna()
            .astype(int)
            .value_counts()
            .head(10)
        )

        if port_counts.empty:
            st.info("No destination-port values in this selection.")
        else:
            port_counts.index = port_counts.index.map(
                lambda port: f"Port {port}"
            )
            port_counts.index.name = "Destination port"
            st.bar_chart(port_counts.rename("Records").to_frame())

        st.caption("Records without a destination port are excluded.")


def render_records(df: pd.DataFrame) -> None:
    """Display and export the filtered records."""
    st.subheader("Explore matching records")

    newest_first = st.checkbox(
        "Show newest records first",
        value=True,
    )

    display_df = df.sort_values(
        "timestamp",
        ascending=not newest_first,
    )

    st.dataframe(
        display_df,
        hide_index=True,
        use_container_width=True,
    )

    st.download_button(
        label="Download filtered records as CSV",
        data=display_df.to_csv(index=False).encode("utf-8"),
        file_name="filtered_network_traffic.csv",
        mime="text/csv",
    )


# ---------- App ----------

def main() -> None:
    st.title("Cybersecurity Traffic Explorer")
    st.write(
        "Explore network activity by date and protocol, compare "
        "traffic patterns, and inspect individual records."
    )

    st.info(
        "Demo mode: all records in this mockup are generated sample "
        "data. This app does not monitor a network or detect attacks."
    )

    df = load_demo_data()

    with st.sidebar:
        st.header("Filter traffic")

        st.caption("Data source: generated demonstration data")

        selected_protocols = st.multiselect(
            "Protocols",
            options=sorted(df["protocol"].unique()),
            default=sorted(df["protocol"].unique()),
        )

        earliest = df["timestamp"].min().date()
        latest = df["timestamp"].max().date()

        selected_dates = st.date_input(
            "Date range",
            value=(earliest, latest),
            min_value=earliest,
            max_value=latest,
        )

        st.divider()
        st.caption(
            "Filters apply to all metrics, charts, "
            "and downloadable records."
        )

    if len(selected_dates) != 2:
        st.warning("Select both a start date and an end date.")
        st.stop()

    start_date, end_date = selected_dates

    filtered_df = filter_traffic(
        df,
        selected_protocols,
        start_date,
        end_date,
    )

    st.caption(
        f"Showing {len(filtered_df):,} of {len(df):,} records "
        f"from {start_date:%b %d, %Y} "
        f"through {end_date:%b %d, %Y}."
    )

    render_metrics(filtered_df)
    st.divider()

    if filtered_df.empty:
        st.warning(
            "No records match these filters. Select a protocol "
            "or expand the date range."
        )
        st.stop()

    render_charts(filtered_df)
    st.divider()
    render_records(filtered_df)

    with st.expander("About this prototype"):
        st.write(
            "This prototype demonstrates an interactive "
            "network-traffic dashboard using reproducible sample "
            "data. Its charts describe record counts and traffic "
            "volume; they do not establish whether activity is "
            "malicious."
        )
        st.write(
            "The next development step is to replace the sample "
            "data loader with a loader for the Kaggle dataset "
            "and map its actual columns to this interface."
        )


if __name__ == "__main__":
    main()