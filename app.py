"""Application entrypoint and page navigation."""

import streamlit as st


st.set_page_config(
    page_title="Cybersecurity Traffic Explorer",
    layout="wide",
)

navigation = st.navigation(
    [
        st.Page(
            "views/overview.py",
            title="Traffic Overview",
            default=True,
        ),
        st.Page(
            "views/investigator.py",
            title="Connection Investigator",
        ),
    ]
)

navigation.run()