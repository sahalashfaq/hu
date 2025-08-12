import streamlit as st
import pandas as pd
import re
import dns.resolver
import smtplib
import requests
import asyncio
import time
from email_validator import validate_email, EmailNotValidError
import io
import dns.exception
from datetime import timedelta

st.set_page_config(page_title="Email Validator Pro", layout="centered")

# Load CSS
def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except:
        st.warning("No CSS loaded.")

load_css()

st.write("Validate Your Extracted Emails")

# Disposable domain loader
@st.cache_data
def fetch_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
    r = requests.get(url)
    return r.text.splitlines() if r.status_code == 200 else []

DISPOSABLE_DOMAINS = fetch_disposable_domains()
FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]

# Validation functions
def validate_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def check_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return True, [str(mx.exchange) for mx in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return False, []

def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return True
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return False

def validate_domain(email):
    domain = email.split('@')[-1]
    mx_exists, mx_records = check_mx_records(domain)
    spf_exists = check_spf_record(domain)
    return mx_exists, spf_exists, mx_records

def validate_mailbox(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_record, timeout=5) as server:
            server.helo("example.com")
            server.mail("test@example.com")
            code, _ = server.rcpt(email)
            return code == 250
    except:
        return False

def is_disposable(email):
    return email.split('@')[-1] in DISPOSABLE_DOMAINS

def is_free_email(email):
    return email.split('@')[-1] in FREE_EMAIL_DOMAINS

def is_catch_all(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = str(mx_records[0].exchange)
        with smtplib.SMTP(mx, timeout=5) as server:
            server.helo("example.com")
            server.mail("test@example.com")
            code, _ = server.rcpt(f"randomaddress1234@{domain}")
            return code == 250
    except:
        return False

def get_deliverability_status(syntax, domain_exists, mailbox_exists, disposable, free, catch_all, mx_exists, spf_exists):
    if not syntax:
        return "Not Deliverable", "Invalid syntax"
    if not domain_exists:
        return "Not Deliverable", "Domain doesn't exist"
    if disposable:
        return "Not Deliverable", "Disposable domain"
    if not mx_exists:
        return "Not Deliverable", "No MX records"
    
    if mailbox_exists:
        if free:
            if catch_all:
                return "Risky", "Catch-all + free email"
            return "Deliverable", "Free email provider"
        if catch_all:
            return "Risky", "Catch-all enabled"
        if not spf_exists:
            return "Risky", "Missing SPF, may be flagged"
        return "Deliverable", "--"
    else:
        if catch_all:
            return "Risky", "Catch-all + mailbox unknown"
        if free:
            return "Deliverable", "Free provider, mailbox unverified but likely valid"
        if not spf_exists:
            return "Risky", "No SPF means spam risk"
        return "Deliverable", "Mailbox unconfirmed but MX/SPF suggest acceptance"

def validate_email_address(email):
    syntax = validate_syntax(email)
    domain_exists, spf_exists, mx_records = validate_domain(email)
    mailbox_exists = validate_mailbox(email) if domain_exists else False
    disposable = is_disposable(email)
    free = is_free_email(email)
    catch_all = is_catch_all(email) if domain_exists else False
    
    deliverability, notes = get_deliverability_status(
        syntax, domain_exists, mailbox_exists, disposable, free, catch_all, 
        domain_exists, spf_exists
    )

    return {
        "Email": email,
        "Syntax Valid": syntax,
        "Domain Valid": domain_exists,
        "Mailbox Exists": mailbox_exists,
        "Disposable Email": disposable,
        "Free Email": free,
        "Catch-All Domain": catch_all,
        "MX Record": domain_exists,
        "SPF Record": spf_exists,
        "Deliverability": deliverability,
        "Notes/Issues": notes
    }

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))

def process_csv_sync(file, email_column):
    file.seek(0)
    df = pd.read_csv(file)
    if email_column not in df.columns:
        st.error(f"CSV file must have the '{email_column}' column.")
        return None

    emails = df[email_column].dropna().unique()
    total = len(emails)
    valid_count, invalid_count, risky_count = 0, 0, 0
    start_time = time.time()

    st.info(f"Total Emails to Process: {total}")
    progress = st.progress(0)
    status_box = st.empty()
    result = []

    for i, email in enumerate(emails):
        result.append(validate_email_address(email))

        if result[-1]['Deliverability'] == "Deliverable":
            valid_count += 1
        elif result[-1]['Deliverability'] == "Risky":
            risky_count += 1
        else:
            invalid_count += 1

        elapsed = time.time() - start_time
        speed = (i + 1) / elapsed if elapsed > 0 else 0
        remaining = total - (i + 1)
        est_time = remaining / speed if speed > 0 else 0
        
        status_box.markdown(f"""
        **Progress:** {i+1}/{total}  
        Valid: {valid_count}  
        Risky: {risky_count}  
        Invalid: {invalid_count}  
        Remaining: {remaining}  
        Speed: {speed:.2f} emails/sec  
        Estimated Time Left: {format_time(est_time)}
        """)

        progress.progress((i + 1) / total)

    final_df = pd.DataFrame(result)
    full = pd.merge(df, final_df, left_on=email_column, right_on="Email", how="left")

    buffer = io.StringIO()
    full.to_csv(buffer, index=False)
    buffer.seek(0)
    return buffer.getvalue()

# File upload and column selection
uploaded = st.file_uploader("Upload CSV", type=["csv"])

if uploaded:
    uploaded.seek(0)
    try:
        df_preview = pd.read_csv(uploaded, nrows=5)
        email_column = st.selectbox("Select the Email Column", options=df_preview.columns)

        if st.button("Start Validation"):
            with st.spinner("Processing... Please wait"):
                uploaded.seek(0)
                output_csv = process_csv_sync(uploaded, email_column)
                if output_csv:
                    st.session_state.output_csv = output_csv
                    st.session_state.ready = True
    except pd.errors.EmptyDataError:
        st.error("The uploaded CSV file is empty or invalid.")

# Download button after processing
if st.session_state.get("ready"):
    st.success("Processing Complete!")
    st.download_button(
        "Download Results CSV",
        st.session_state.output_csv,
        file_name="validated_results.csv",
        mime="text/csv"
    )
