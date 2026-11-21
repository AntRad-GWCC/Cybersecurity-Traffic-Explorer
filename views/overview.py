"""Interactive dashboard for exploring cybersecurity traffic records."""

import hashlib
import time
from math import gcd

import pandas as pd
import plotly.express as px
import streamlit as st

from data_utils import filter_traffic, format_bytes, load_data


# Page configuration is handled by the root app.py entrypoint.


ANIMATION_DURATIONS = {
    "Slow": 12.0,
    "Medium": 8.0,
    "Fast": 4.0,
}

ANIMATION_SIGNATURE_KEY = "overview_last_activity_signature"


# ---------- Summary metrics ----------

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


# ---------- Activity animation ----------

def build_activity_signature(
    daily_activity: pd.DataFrame,
    filter_signature: tuple,
) -> str:
    """Identify the chart data and filters used for the current view."""
    signature_text = (
        repr(filter_signature)
        + "\n"
        + daily_activity.to_csv()
    )

    return hashlib.sha256(
        signature_text.encode("utf-8")
    ).hexdigest()


def render_activity_chart(
    df: pd.DataFrame,
    filter_signature: tuple,
) -> None:
    """Display daily activity with automatic and manual playback."""
    st.subheader("Network activity over time")

    st.caption(
        "Each point represents one day. The chart automatically "
        "plays at Medium speed when first loaded or when the "
        "date or protocol filters change."
    )

    daily_activity = (
        df.set_index("timestamp")
        .resample("D")
        .size()
        .rename("Records")
        .to_frame()
    )

    chart_signature = build_activity_signature(
        daily_activity,
        filter_signature,
    )

    previous_signature = st.session_state.get(
        ANIMATION_SIGNATURE_KEY
    )

    auto_play = previous_signature != chart_signature
    can_animate = len(daily_activity) >= 2

    controls_col, speed_col = st.columns([2, 1])

    with controls_col:
        play_animation = st.button(
            "Play activity animation",
            key="overview_play_activity_animation",
            disabled=not can_animate,
        )

    with speed_col:
        animation_speed = st.selectbox(
            "Replay speed",
            options=list(ANIMATION_DURATIONS),
            index=1,
            key="overview_activity_animation_speed",
            help=(
                "Controls manual replay. Automatic playback "
                "always uses Medium speed."
            ),
        )

    chart_placeholder = st.empty()

    # Manual replay uses the selected speed.
    # Automatic playback always uses Medium.
    playback_speed = (
        animation_speed if play_animation else "Medium"
    )

    should_animate = (
        can_animate
        and (play_animation or auto_play)
    )

    if should_animate:
        duration_seconds = ANIMATION_DURATIONS[playback_speed]

        # Bound the number of chart redraws for longer datasets.
        frame_count = min(len(daily_activity), 60)

        endpoints = [
            1 + round(
                frame * (len(daily_activity) - 1)
                / (frame_count - 1)
            )
            for frame in range(frame_count)
        ]

        # Remove duplicate endpoints while retaining their order.
        endpoints = list(dict.fromkeys(endpoints))

        frame_interval = (
            duration_seconds / (len(endpoints) - 1)
        )

        animation_start = time.monotonic()

        with st.spinner(
            f"Playing activity at {playback_speed.lower()} speed..."
        ):
            for frame_index, end in enumerate(endpoints):
                target_time = (
                    animation_start
                    + frame_index * frame_interval
                )

                remaining = target_time - time.monotonic()

                if remaining > 0:
                    time.sleep(remaining)

                chart_placeholder.line_chart(
                    daily_activity.iloc[:end],
                    color="#38BDF8",
                    height=320,
                )

    else:
        chart_placeholder.line_chart(
            daily_activity,
            color="#38BDF8",
            height=320,
        )

    # Record the signature after rendering completes.
    st.session_state[ANIMATION_SIGNATURE_KEY] = chart_signature

    if not can_animate:
        st.caption(
            "At least two days of activity are needed "
            "for animation."
        )
    else:
        st.caption(
            "Manual replay: Slow ≈ 12 seconds, Medium ≈ 8 seconds, "
            "Fast ≈ 4 seconds. This is a replay of dataset records, "
            "not a live network feed."
        )


# ---------- Comparison charts ----------

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


# ---------- Records table ----------

def render_records(df: pd.DataFrame) -> None:
    """Display and export the filtered records."""
    st.subheader("Explore matching records")

    newest_first = st.checkbox(
        "Show newest records first",
        value=True,
        key="overview_newest_first",
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
        key="overview_download_records",
    )


# ---------- Source activity ----------

def render_source_summary(df: pd.DataFrame) -> None:
    """Identify the most active sources by record count."""
    source_counts = df["source_ip"].dropna().value_counts()

    if source_counts.empty:
        st.info("No source IP addresses are available.")
        return

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
        "Records per leading source",
        f"{highest_count:,}",
    )

    share_col.metric(
        "Share per leading source",
        f"{highest_count / len(df):.2%}",
    )

    if len(leaders) > 1:
        st.caption(
            f"{len(leaders):,} source IPs tie at "
            f"{highest_count:,} record(s) each. "
            "There is no unique most-active source by record count."
        )

    with st.expander("View up to 10 leading source IPs"):
        ranking = (
            source_counts
            .rename_axis("Source IP")
            .reset_index(name="Records")
            .sort_values(
                ["Records", "Source IP"],
                ascending=[False, True],
            )
            .head(10)
        )

        ranking["Share of filtered records (%)"] = (
            ranking["Records"] / len(df) * 100
        ).round(2)

        st.dataframe(
            ranking,
            hide_index=True,
            use_container_width=True,
        )

        st.caption(
            "Tied sources are ordered by their IP address text. "
            "Only the first 10 are displayed."
        )


# ---------- Attack insights ----------

def render_security_summary(df: pd.DataFrame) -> None:
    """Summarize source activity and dataset-provided labels."""
    st.subheader("Traffic and attack insights")

    st.caption(
        "All results reflect the current overview filters. "
        "Activity is measured by record count, not threat severity."
    )

    if df.empty:
        st.info("No records are available for this selection.")
        return

    render_source_summary(df)

    st.divider()

    if "traffic_label" not in df.columns:
        st.info(
            "Attack analysis is unavailable because a "
            "traffic_label column has not been provided "
            "by the data loader."
        )
        return

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

    with type_col:
        st.markdown("### Distribution of attack types")

        if attack_count == 0:
            st.info("No labeled attacks in this selection.")

        elif "attack_type" not in df.columns:
            st.info(
                "Attack labels are available, but an attack-type "
                "column has not been mapped."
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
        common_divisor = gcd(attack_count, normal_count)

        attack_part = attack_count // common_divisor
        normal_part = normal_count // common_divisor

        ratio_col.metric(
            "Attack-to-normal ratio",
            f"{attack_part}:{normal_part}",
            help=(
                "Exact reduced ratio of attack-labeled records "
                "to normal-labeled records."
            ),
        )

    else:
        ratio_col.metric(
            "Attack-to-normal ratio",
            "N/A",
        )

        st.caption(
            "The attack-to-normal quotient is undefined because "
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


# ---------- About ----------

def render_about() -> None:
    """Explain the dashboard's purpose and limitations."""
    with st.expander("About this dashboard"):
        st.write(
            "This dashboard explores records from the Kaggle "
            "Cybersecurity Threat Detection Dataset stored "
            "in cybersecurity.csv."
        )

        st.write(
            "Filters apply to the summary metrics, charts, "
            "records table, and downloadable CSV. Attack charts "
            "use the classifications supplied in the dataset."
        )

        st.write(
            "The activity animation replays historical records. "
            "It is not a live network feed or an independent "
            "intrusion-detection system."
        )

        st.write(
            "Source activity is measured by record count. "
            "If multiple addresses have the same highest count, "
            "the dashboard reports a tie rather than choosing "
            "an arbitrary winner."
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

        st.caption("Data source: cybersecurity.csv")

        protocol_options = sorted(
            df["protocol"].dropna().unique().tolist()
        )

        selected_protocols = st.multiselect(
            "Protocols",
            options=protocol_options,
            default=protocol_options,
            key="overview_protocols",
        )

        earliest = df["timestamp"].min().date()
        latest = df["timestamp"].max().date()

        selected_dates = st.date_input(
            "Date range",
            value=(earliest, latest),
            min_value=earliest,
            max_value=latest,
            key="overview_dates",
        )

        st.divider()

        st.caption(
            "Filters apply to all metrics, charts, "
            "and downloadable records."
        )

    if len(selected_dates) != 2:
        # Replay when a complete date selection is restored.
        st.session_state.pop(
            ANIMATION_SIGNATURE_KEY,
            None,
        )

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
        # Replay when the user returns to a nonempty selection.
        st.session_state.pop(
            ANIMATION_SIGNATURE_KEY,
            None,
        )

        st.warning(
            "No records match these filters. Select a protocol "
            "or expand the date range."
        )

        render_about()
        st.stop()

    filter_signature = (
        tuple(sorted(selected_protocols)),
        start_date.isoformat(),
        end_date.isoformat(),
    )

    render_activity_chart(
        filtered_df,
        filter_signature,
    )

    st.divider()

    render_security_summary(filtered_df)

    st.divider()

    render_comparison_charts(filtered_df)

    st.divider()

    render_records(filtered_df)

    render_about()


if __name__ == "__main__":
    main()