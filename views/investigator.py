"""Source-IP investigation page for the traffic explorer."""

import pandas as pd
import streamlit as st

from data_utils import filter_traffic, format_bytes, load_demo_data


def render_metrics(df: pd.DataFrame) -> None:
    """Summarize the records belonging to the selected source."""
    records_col, destinations_col, sent_col, received_col = st.columns(4)

    records_col.metric(
        "Matching records",
        f"{len(df):,}",
    )

    destinations_col.metric(
        "Destinations contacted",
        f"{df['destination_ip'].nunique():,}",
    )

    sent_col.metric(
        "Bytes sent",
        format_bytes(df["bytes_sent"].sum()),
    )

    received_col.metric(
        "Bytes received",
        format_bytes(df["bytes_received"].sum()),
    )


def render_source_profile(
    source_ip: str,
    df: pd.DataFrame,
) -> None:
    """Display the source's observed activity within the filters."""
    st.subheader("Source profile")

    first_seen = df["timestamp"].min()
    last_seen = df["timestamp"].max()
    protocols = ", ".join(sorted(df["protocol"].unique()))

    source_col, first_col, last_col = st.columns(3)

    source_col.markdown("Source IP")
    source_col.code(source_ip, language=None)

    first_col.markdown("First observed in selection")
    first_col.write(first_seen.strftime("%b %d, %Y · %H:%M:%S"))

    last_col.markdown("Last observed in selection")
    last_col.write(last_seen.strftime("%b %d, %Y · %H:%M:%S"))

    st.caption(f"Protocols observed in selection: {protocols}")


def render_activity_chart(df: pd.DataFrame) -> None:
    """Display daily record counts separated by protocol."""
    st.subheader("Source activity over time")

    st.caption(
        "Daily record counts for the selected source, "
        "with a separate line for each protocol."
    )

    daily_activity = (
        df.groupby(
            [
                pd.Grouper(key="timestamp", freq="D"),
                "protocol",
            ]
        )
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )

    # Include inactive days between the first and last observed dates.
    full_date_range = pd.date_range(
        start=df["timestamp"].min().normalize(),
        end=df["timestamp"].max().normalize(),
        freq="D",
    )

    daily_activity = daily_activity.reindex(
        full_date_range,
        fill_value=0,
    )
    daily_activity.index.name = "Date"

    if len(daily_activity) == 1:
        st.bar_chart(daily_activity, height=320)
    else:
        st.line_chart(daily_activity, height=320)


def render_destination_charts(
    df: pd.DataFrame,
    top_n: int,
) -> None:
    """Rank destination addresses and destination ports."""
    destinations_col, ports_col = st.columns(2)

    with destinations_col:
        st.subheader("Top destination IPs")

        destination_counts = (
            df["destination_ip"]
            .value_counts()
            .head(top_n)
            .rename_axis("Destination IP")
            .rename("Records")
            .to_frame()
        )

        st.bar_chart(
            destination_counts,
            horizontal=True,
            color="#38BDF8",
            height=350,
        )

        st.caption(
            "Ranked by matching record count, not by threat level."
        )

    with ports_col:
        st.subheader("Top destination ports")

        port_counts = (
            df["destination_port"]
            .dropna()
            .astype(int)
            .value_counts()
            .head(top_n)
        )

        if port_counts.empty:
            st.info(
                "The selected records do not contain "
                "destination-port values."
            )
        else:
            port_counts.index = port_counts.index.map(
                lambda port: f"Port {port}"
            )
            port_counts.index.name = "Destination port"

            st.bar_chart(
                port_counts.rename("Records").to_frame(),
                horizontal=True,
                color="#2DD4BF",
                height=350,
            )

        st.caption(
            "Records without destination ports are excluded."
        )


def render_records(
    df: pd.DataFrame,
    source_ip: str,
) -> None:
    """Display and export the investigation's matching records."""
    st.subheader("Investigation records")

    newest_first = st.checkbox(
        "Show newest records first",
        value=True,
        key="investigator_newest_first",
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
        label="Download investigation records",
        data=display_df.to_csv(index=False).encode("utf-8"),
        file_name=f"investigation_{source_ip.replace('.', '_')}.csv",
        mime="text/csv",
        key="investigator_download",
    )


def main() -> None:
    st.title("Connection Investigator")

    st.write(
        "Focus on one source IP to explore when it was active, "
        "which destinations it contacted, and how much data "
        "appears in its records."
    )

    st.info(
        "Demo mode: these are generated sample records. "
        "This page describes network activity; it does not "
        "determine whether a connection is malicious."
    )

    df = load_demo_data()

    # Sort generated IPv4 addresses numerically rather than alphabetically.
    source_options = sorted(
        df["source_ip"].dropna().unique().tolist(),
        key=lambda address: tuple(
            int(part) for part in address.split(".")
        ),
    )

    with st.sidebar:
        st.header("Investigation filters")

        selected_source = st.selectbox(
            "Source IP",
            options=source_options,
            key="investigator_source_ip",
        )

        protocol_options = sorted(
            df["protocol"].dropna().unique().tolist()
        )

        selected_protocols = st.multiselect(
            "Protocols",
            options=protocol_options,
            default=protocol_options,
            key="investigator_protocols",
        )

        earliest = df["timestamp"].min().date()
        latest = df["timestamp"].max().date()

        selected_dates = st.date_input(
            "Date range",
            value=(earliest, latest),
            min_value=earliest,
            max_value=latest,
            key="investigator_dates",
        )

        top_n = st.slider(
            "Maximum items in destination charts",
            min_value=5,
            max_value=20,
            value=10,
            step=5,
            key="investigator_top_n",
        )

        st.divider()

        st.caption(
            "These filters apply to this investigation page. "
            "They are separate from the overview filters."
        )

    if len(selected_dates) != 2:
        st.warning("Select both a start date and an end date.")
        st.stop()

    start_date, end_date = selected_dates

    source_df = df.loc[
        df["source_ip"] == selected_source
    ].copy()

    filtered_df = filter_traffic(
        source_df,
        selected_protocols,
        start_date,
        end_date,
    )

    st.caption(
        f"Investigating {selected_source} · "
        f"{start_date:%b %d, %Y} through "
        f"{end_date:%b %d, %Y} · "
        f"{len(filtered_df):,} matching records"
    )

    render_metrics(filtered_df)

    if filtered_df.empty:
        st.warning(
            "No records match this investigation. "
            "Choose another source IP, select a protocol, "
            "or expand the date range."
        )
        st.stop()

    st.divider()

    render_source_profile(selected_source, filtered_df)

    st.divider()

    render_activity_chart(filtered_df)

    st.divider()

    render_destination_charts(filtered_df, top_n)

    st.divider()

    render_records(filtered_df, selected_source)

    with st.expander("How to interpret this page"):
        st.write(
            "All metrics and charts summarize records that match "
            "the selected source IP, protocols, and date range."
        )

        st.write(
            "First and last observed times refer only to the "
            "filtered records, not the lifetime of the device. "
            "Destination rankings count records rather than "
            "confirmed connections or attacks."
        )

        st.write(
            "The sample data is randomly generated. Its activity "
            "patterns are for demonstrating the dashboard, "
            "not for drawing real cybersecurity conclusions."
        )


if __name__ == "__main__":
    main()