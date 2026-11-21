"""Interactive dashboard for exploring sample network traffic."""

import time
import pandas as pd
import streamlit as st
import plotly.express as px

from data_utils import filter_traffic, format_bytes, load_data


# ---------- Page setup ----------

st.set_page_config(
    page_title="Cybersecurity Traffic Explorer",
    page_icon=None,
    layout="wide",
)


# ---------- Interface components ----------

def render_metrics(df: pd.DataFrame) -> None:
    """Show summary values for the current selection."""
    records_col, sent_col, received_col, sources_col = st.columns(4)

    records_col.metric(
        "Matching records",
        f"{len(df):,}",
    )

    sent_col.metric(
        "Bytes sent",
        format_bytes(df["bytes_sent"].sum()),
    )

    received_col.metric(
        "Bytes received",
        format_bytes(df["bytes_received"].sum()),
    )

    sources_col.metric(
        "Unique source IPs",
        f"{df['source_ip'].nunique():,}",
    )


def render_activity_chart(df: pd.DataFrame) -> None:
    """Display daily activity with an optional progressive animation."""
    st.subheader("Network activity over time")

    st.caption(
        "Each point represents one day. Play the animation "
        "to reveal the selected period from left to right."
    )

    daily_activity = (
        df.set_index("timestamp")
        .resample("D")
        .size()
        .rename("Records")
        .to_frame()
    )

    controls_col, speed_col = st.columns([2, 1])

    with controls_col:
        play_animation = st.button(
            "Play activity animation",
            key="play_activity_animation",
            disabled=len(daily_activity) < 2,
        )

    with speed_col:
        animation_speed = st.selectbox(
            "Animation speed",
            options=["Slow", "Normal", "Fast"],
            index=1,
            key="activity_animation_speed",
        )

    chart_placeholder = st.empty()

    if play_animation and len(daily_activity) >= 2:
        duration_seconds = {
            "Slow": 6.0,
            "Normal": 3.0,
            "Fast": 1.0,
        }[animation_speed]

        # Limit redraws for datasets covering longer periods.
        frame_count = min(len(daily_activity), 40)

        endpoints = sorted(
            {
                1 + round(
                    frame * (len(daily_activity) - 1)
                    / (frame_count - 1)
                )
                for frame in range(frame_count)
            }
        )

        delay = duration_seconds / max(len(endpoints) - 1, 1)

        for frame_index, end in enumerate(endpoints):
            chart_placeholder.line_chart(
                daily_activity.iloc[:end],
                color="#38BDF8",
                height=320,
            )

            if frame_index < len(endpoints) - 1:
                time.sleep(delay)

    else:
        chart_placeholder.line_chart(
            daily_activity,
            color="#38BDF8",
            height=320,
        )

    if len(daily_activity) < 2:
        st.caption(
            "Select a date range containing at least two days "
            "to play the animation."
        )


def render_comparison_charts(df: pd.DataFrame) -> None:
    """Compare protocols and destination-port frequencies."""
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

        st.bar_chart(
            protocol_counts,
            color="#38BDF8",
            height=300,
        )

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
            st.info(
                "No destination-port values in this selection."
            )
        else:
            port_counts.index = port_counts.index.map(
                lambda port: f"Port {port}"
            )
            port_counts.index.name = "Destination port"

            st.bar_chart(
                port_counts.rename("Records").to_frame(),
                color="#2DD4BF",
                height=300,
            )

        st.caption(
            "Records without a destination port are excluded."
        )


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


def render_about() -> None:
    """Explain the prototype's purpose and limitations."""
    with st.expander("About this prototype"):
        st.write(
            "This prototype demonstrates an interactive "
            "network-traffic dashboard using reproducible "
            "sample data. Its charts describe record counts "
            "and traffic volume; they do not establish "
            "whether activity is malicious."
        )

        st.write(
            "The animation replays the selected sample data. "
            "It is not a live network feed."
        )

        st.write(
            "The next development step is to replace the "
            "sample data loader with a loader for the Kaggle "
            "dataset and map its actual columns to this "
            "interface."
        )

def render_security_summary(df: pd.DataFrame) -> None:
    """Summarize source activity and verified dataset labels."""
    st.subheader("Traffic and attack insights")

    st.caption(
        "All results reflect the current overview filters. "
        "Activity is measured by record count, not threat severity."
    )

    if df.empty:
        st.info("No records are available for this selection.")
        return

    # ---------- Most active source ----------

    source_counts = df["source_ip"].dropna().value_counts()

    if source_counts.empty:
        st.info("No source IP addresses are available.")
    else:
        highest_count = int(source_counts.max())
        leaders = source_counts[
            source_counts == highest_count
        ].index.tolist()

        activity_col, count_col, share_col = st.columns(3)

        activity_col.metric(
            "Most active source IP",
            str(leaders[0]) if len(leaders) == 1 else "Multiple tied",
        )

        count_col.metric(
            "Records from this source",
            f"{highest_count:,}",
        )

        share_col.metric(
            "Share of filtered records",
            f"{highest_count / len(df):.1%}",
        )

        if len(leaders) > 1:
            st.caption(
                f"{len(leaders):,} source IPs tie at "
                f"{highest_count:,} record(s) each. "
                "There is no unique most-active source by record count."
            )

        with st.expander("View the top 10 source IPs"):
            ranking = (
                source_counts.head(10)
                .rename_axis("Source IP")
                .reset_index(name="Records")
            )

            ranking["Share of filtered records (%)"] = (
                ranking["Records"] / len(df) * 100
            ).round(2)

            st.dataframe(
                ranking,
                hide_index=True,
                use_container_width=True,
            )

    st.divider()

    # ---------- Verified traffic classification ----------

    if "traffic_label" not in df.columns:
        st.info(
            "Attack analysis is not available yet. The current "
            "sample data has no attack labels. After we connect "
            "the real CSV, we will map its verified classification "
            "and attack-type columns."
        )
        return

    # Accept only explicitly mapped Attack/Normal values.
    # Missing or unexpected values remain unclassified.
    labels = (
        df["traffic_label"]
        .astype("string")
        .str.strip()
        .str.casefold()
        .map(
            {
                "attack": "Attack",
                "normal": "Normal",
            }
        )
    )

    attack_mask = labels.eq("Attack").fillna(False)
    normal_mask = labels.eq("Normal").fillna(False)

    attack_count = int(attack_mask.sum())
    normal_count = int(normal_mask.sum())
    classified_count = attack_count + normal_count
    unclassified_count = len(df) - classified_count

    if classified_count == 0:
        st.warning(
            "No recognized Attack or Normal labels are available "
            "in this selection. Check the dataset label mapping."
        )
        return

    type_col, balance_col = st.columns(2)

    # ---------- Attack-type distribution ----------

    with type_col:
        st.markdown("### Distribution of attack types")

        if attack_count == 0:
            st.info("No labeled attacks in this selection.")

        elif "attack_type" not in df.columns:
            st.info(
                "Attack labels are available, but an attack-type "
                "column has not been mapped yet."
            )

        else:
            attack_types = (
                df.loc[attack_mask, "attack_type"]
                .astype("string")
                .str.strip()
                .replace("", pd.NA)
                .fillna("Unspecified")
            )

            type_counts = (
                attack_types.value_counts()
                .rename_axis("Attack type")
                .reset_index(name="Records")
            )

            type_figure = px.pie(
                type_counts,
                names="Attack type",
                values="Records",
                hole=0.35,
            )

            type_figure.update_traces(
                textinfo="percent",
                hovertemplate=(
                    "%{label}<br>"
                    "Records: %{value:,}<br>"
                    "Share of labeled attacks: %{percent}"
                    "<extra></extra>"
                ),
            )

            type_figure.update_layout(
                margin=dict(t=20, b=20, l=10, r=10),
                legend_title_text="Attack type",
            )

            st.plotly_chart(
                type_figure,
                use_container_width=True,
                key="overview_attack_type_pie",
            )

            st.caption(
                "Percentages use labeled attack records only. "
                "Missing attack categories appear as Unspecified."
            )

    # ---------- Attack-versus-normal distribution ----------

    with balance_col:
        st.markdown("### Attacks vs normal traffic")

        balance = pd.DataFrame(
            {
                "Classification": ["Attack", "Normal"],
                "Records": [attack_count, normal_count],
            }
        )

        balance_figure = px.pie(
            balance,
            names="Classification",
            values="Records",
            hole=0.55,
            color="Classification",
            color_discrete_map={
                "Attack": "#F87171",
                "Normal": "#2DD4BF",
            },
        )

        balance_figure.update_traces(
            textinfo="label+percent",
            hovertemplate=(
                "%{label}<br>"
                "Records: %{value:,}<br>"
                "Share of classified records: %{percent}"
                "<extra></extra>"
            ),
        )

        balance_figure.update_layout(
            margin=dict(t=20, b=20, l=10, r=10),
            showlegend=False,
        )

        st.plotly_chart(
            balance_figure,
            use_container_width=True,
            key="overview_attack_normal_pie",
        )

        st.caption(
            "Percentages use records classified as Attack or "
            "Normal; unclassified records are excluded."
        )

    # ---------- Counts and ratio ----------

    attack_col, normal_col, ratio_col = st.columns(3)

    attack_col.metric(
        "Labeled attacks",
        f"{attack_count:,}",
        help=(
            f"{attack_count / classified_count:.1%} "
            "of classified records"
        ),
    )

    normal_col.metric(
        "Labeled normal",
        f"{normal_count:,}",
        help=(
            f"{normal_count / classified_count:.1%} "
            "of classified records"
        ),
    )

    if normal_count > 0:
        ratio_col.metric(
            "Attack-to-normal ratio",
            f"{attack_count / normal_count:.2f}:1",
        )
    else:
        ratio_col.metric(
            "Attack-to-normal ratio",
            "N/A",
        )
        st.caption(
            "The attack-to-normal ratio is undefined because "
            "there are no labeled normal records."
        )

    if unclassified_count:
        st.warning(
            f"{unclassified_count:,} records have missing or "
            "unrecognized classification labels and are excluded "
            "from attack-versus-normal calculations."
        )

    st.caption(
        "These are dataset-provided designations, "
        "not attacks independently detected by this app."
    )

# ---------- App ----------

def main() -> None:
    st.title("Cybersecurity Traffic Explorer")

    st.write(
        "Explore network activity by date and protocol, "
        "compare traffic patterns, and inspect individual records."
    )

    st.info(
        "Data source: Kaggle Cybersecurity Threat Detection Dataset. "
        "Attack classifications come from the dataset labels; "
        "this app does not independently detect attacks."
    )

    df = load_data()

    with st.sidebar:
        st.header("Filter traffic")

        st.caption(
            "Data source: cybersecurity.csv"
        )

        protocol_options = sorted(
            df["protocol"].unique().tolist()
        )

        selected_protocols = st.multiselect(
            "Protocols",
            options=protocol_options,
            default=protocol_options,
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
        st.warning(
            "Select both a start date and an end date."
        )
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
        render_about()
        st.stop()

    render_activity_chart(filtered_df)
    
    st.divider()
    
    render_security_summary(filtered_df)

    st.divider()

    render_activity_chart(filtered_df)
    
    st.divider()

    render_comparison_charts(filtered_df)

    st.divider()

    render_records(filtered_df)

    render_about()

if __name__ == "__main__":
    main()