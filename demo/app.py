"""Thin Streamlit demo for machine-identity security (lazy import)."""

try:
    import streamlit as st
except ImportError:  # pragma: no cover
    raise SystemExit("pip install streamlit to run the demo") from None


def main() -> None:
    from midsec import demo_helpers

    st.title("Machine Identity Security — posture agent")
    out = demo_helpers.sample_run()

    st.subheader("Ranked remediation list")
    st.table([{"identity": r["id"], "risk": r["risk"],
               "flags": ", ".join(r["flags"])}
              for r in out["ranked"][:8]])

    st.subheader("Threat findings")
    st.table([{"signal": f["signal_id"], "identity": f["identity_id"],
               "severity": f["severity"], "detail": f["detail"]}
              for f in out["findings"]])

    st.subheader("Agent outcome (dry-run)")
    st.write(f"auto-executed: {len(out['executed'])}, "
             f"escalated: {len(out['escalated'])}")


if __name__ == "__main__":
    main()
