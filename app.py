import streamlit as st
from checker import build_report, validate_url

st.set_page_config(page_title="Web Health Scanner", page_icon="🔍")
st.title("🔍 Web Health Scanner")
st.write("Check a website's health, security headers, and SSL certificate.")

url_input = st.text_input("Enter URL", placeholder="example.com")

if st.button("Scan"):
    valid, result = validate_url(url_input)

    if not valid:
        st.error(result)
    else:
        with st.spinner("Scanning..."):
            report = build_report(result)

        st.subheader(f"Report for {report['url']}")

        col1, col2, col3 = st.columns(3)
        col1.metric("Reachable", "Yes" if report["health"]["reachable"] else "No")
        col2.metric("Status Code", report["health"]["status_code"])
        col3.metric("Score", f"{report['score']}/10")

        if report["health"]["reachable"]:
            st.metric("Response Time", f"{report['health']['response_time_ms']} ms")

            st.subheader("Security Headers")
            for header, present in report["security_headers"].items():
                if present:
                    st.success(f"✅ {header}: Present")
                else:
                    st.warning(f"⚠️ {header}: Missing")

            st.subheader("SSL Certificate")
            ssl_info = report["ssl"]
            if ssl_info["valid"]:
                st.success(f"Valid — expires in {ssl_info['days_until_expiry']} days ({ssl_info['expires_on']})")
            else:
                st.error(f"Invalid: {ssl_info['error']}")

            st.subheader("Redirects")
            st.write(f"Redirect count: {report['redirect']['redirect_count']}")
            st.write(f"Forces HTTPS: {report['redirect']['forces_https']}")

        st.download_button(
            "Download JSON report",
            data=str(report),
            file_name="report.json"
        )