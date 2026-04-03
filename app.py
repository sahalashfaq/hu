import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
import requests
import time
import random
import string
from email_validator import validate_email, EmailNotValidError
import io
import dns.exception
from datetime import timedelta

st.set_page_config(page_title="Email Validator Pro", layout="centered")

def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except:
        pass

load_css()

st.markdown("<p class='h1 h'>Email <span>Validator</span></p>", unsafe_allow_html=True)

# ==================== CONFIG ====================

@st.cache_data(ttl=86400)
def fetch_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return {line.strip().lower() for line in r.text.splitlines() if line.strip() and not line.startswith('#')}
    except:
        st.warning("Failed to fetch latest disposable list.")
    return set()

DISPOSABLE_DOMAINS = fetch_disposable_domains()

# Significantly expanded extra disposable / temporary domains (2026 popular ones)
EXTRA_DISPOSABLE = {
    "tempmail.org", "tempmail.net", "throwawaymail.com", "guerrillamailblock.com",
    "disposable-mail.com", "sharklasers.com", "trashmail.com", "10minutemail.com",
    "maildrop.cc", "tempemail.cc", "getnada.com", "mohmal.com", "dispostable.com",
    "emailondeck.com", "fakeinbox.com", "grr.la", "mailnesia.com", "tempinbox.com",
    "tempail.com", "throwaway.email", "mailinator2.com", "binkmail.com", "bobmail.info",
    "chammy.info", "devnullmail.com", "letthemeatspam.com", "reallymymail.com",
    "reconmail.com", "safetymail.info", "sendspamhere.com", "sogetthis.com",
    "spambooger.com", "spamherelots.com", "spamhereplease.com", "20minutemail.com",
    "30minutemail.com", "mail.lukasstorck.com", "pro.anonymail.co", "shootstack.net",
    "kriscop.online", "tsaur.com", "furusato.dev", "0-mail.com", "0815.ru", "0clickemail.com",
    "0wnd.net", "0wnd.org", "1fsdfdsfsdf.tk", "1pad.de", "2fdgdfgdfgdf.tk"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com",
    "protonmail.com", "proton.me", "zoho.com", "yandex.com", "mail.com", "gmx.com",
    "live.com", "msn.com", "comcast.net", "verizon.net", "tutanota.com", "tuta.com"
}

# ==================== VALIDATION FUNCTIONS ====================

def validate_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def check_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return True, [str(mx.exchange).rstrip('.') for mx in mx_records]
    except:
        return False, []

def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata).lower():
                return True
        return False
    except:
        return False

def is_disposable(email):
    domain = email.split('@')[-1].lower()
    return domain in DISPOSABLE_DOMAINS or domain in EXTRA_DISPOSABLE

def is_free_email(email):
    domain = email.split('@')[-1].lower()
    return domain in FREE_EMAIL_DOMAINS

def is_catch_all(domain):
    domain = domain.lower()
    if domain in FREE_EMAIL_DOMAINS:
        return False
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = str(mx_records[0].exchange).rstrip('.')
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=24))
        test_email = f"test{random_str}@{domain}"
        
        with smtplib.SMTP(mx, timeout=8) as server:
            server.helo("validator.pro")
            server.mail("test@example.com")
            code, _ = server.rcpt(test_email)
            return code == 250
    except:
        return False

def validate_mailbox(email):
    try:
        domain = email.split('@')[-1].lower()
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = str(mx_records[0].exchange).rstrip('.')
        with smtplib.SMTP(mx, timeout=8) as server:
            server.helo("validator.pro")
            server.mail("test@example.com")
            code, _ = server.rcpt(email)
            return code == 250
    except:
        return False

def get_deliverability_status(syntax, domain_exists, mailbox_exists, disposable, free, catch_all, spf_exists):
    if not syntax:
        return "Not Deliverable", "Invalid syntax"
    if not domain_exists:
        return "Not Deliverable", "Domain doesn't exist"
    if disposable:
        return "Not Deliverable", "Disposable domain"
    
    if free:
        if mailbox_exists:
            return "Deliverable", "Free email provider - mailbox confirmed"
        return "Deliverable", "Free email provider - mailbox unverified"

    # Non-free domains
    if mailbox_exists:
        if catch_all:
            return "Risky", "Catch-all enabled"
        if not spf_exists:
            return "Risky", "Missing SPF"
        return "Deliverable", "Mailbox exists"
    else:
        if catch_all:
            return "Risky", "Catch-all domain"
        if not spf_exists:
            return "Risky", "No SPF - higher risk"
        return "Deliverable", "Mailbox unconfirmed (MX/SPF OK)"

def validate_email_address(email):
    syntax = validate_syntax(email)
    domain = email.split('@')[-1].lower() if '@' in email else ""

    mx_exists = False
    spf_exists = False
    if syntax and domain:
        mx_exists, _ = check_mx_records(domain)
        spf_exists = check_spf_record(domain)

    mailbox_exists = validate_mailbox(email) if syntax and mx_exists else False
    disposable = is_disposable(email) if syntax else False
    free = is_free_email(email) if syntax else False
    catch_all = is_catch_all(domain) if syntax and mx_exists and not free and not disposable else False

    deliverability, notes = get_deliverability_status(
        syntax, mx_exists, mailbox_exists, disposable, free, catch_all, spf_exists
    )

    return {
        "Email": email,
        "Deliverability": deliverability,
        "Notes/Issues": notes,
        "Syntax Valid": syntax,
        "Domain Valid": mx_exists,
        "Mailbox Exists": mailbox_exists,
        "Disposable Email": disposable,
        "Free Email": free,
        "Catch-All Domain": catch_all,
        "SPF Record": spf_exists
    }

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))

# ==================== LIVE PROCESSING WITH COLOR CODING ====================

def process_csv_with_live_output(file, email_column):
    file.seek(0)
    df = pd.read_csv(file)

    if email_column not in df.columns:
        st.error(f"Column '{email_column}' not found!")
        return None, None

    unique_emails = set()
    for cell in df[email_column].dropna():
        parts = [p.strip() for p in str(cell).split(' * ') if p.strip()]
        unique_emails.update(parts)

    total = len(unique_emails)
    final_results = []
    valid = risky = invalid = 0
    start_time = time.time()

    progress_bar = st.progress(0)
    status_text = st.empty()
    live_table = st.empty()

    for i, email in enumerate(unique_emails):
        result = validate_email_address(email)
        final_results.append(result)

        if result['Deliverability'] == "Deliverable":
            valid += 1
        elif result['Deliverability'] == "Risky":
            risky += 1
        else:
            invalid += 1

        elapsed = time.time() - start_time
        speed = (i + 1) / elapsed if elapsed > 0 else 0
        remaining = total - (i + 1)
        est = remaining / speed if speed > 0 else 0

        status_text.markdown(f"""
        **Progress:** {i+1}/{total}  
        Deliverable: **{valid}**   
        Risky: **{risky}**   
        Not Deliverable: **{invalid}**  
        Speed: **{speed:.1f}** emails/sec | ETA: **{format_time(est)}**
        """)

        progress_bar.progress((i + 1) / total)

        # Color-coded live table
        live_df = pd.DataFrame(final_results)
        styled_df = live_df.style.apply(
            lambda x: [
                'background-color: #d4edda; color: #155724' if val == 'Deliverable' else
                'background-color: #fff3cd; color: #856404' if val == 'Risky' else
                'background-color: #f8d7da; color: #721c24' 
                for val in x
            ] if x.name == 'Deliverability' else [''] * len(x),
            axis=1
        )
        live_table.dataframe(styled_df, use_container_width=True, height=650)

    # Merge results back to original df
    val_dict = {r['Email']: r for r in final_results}

    for prefix in ['Primary', 'Secondary']:
        df[f'{prefix}_Email'] = ''
        for key in ['Deliverability', 'Notes/Issues', 'Syntax Valid', 'Domain Valid',
                    'Mailbox Exists', 'Disposable Email', 'Free Email', 
                    'Catch-All Domain', 'SPF Record']:
            df[f'{prefix}_{key}'] = ''

    for index, row in df.iterrows():
        cell = row[email_column]
        if pd.isna(cell):
            continue
        parts = [p.strip() for p in str(cell).split(' * ') if p.strip()]
        primary = parts[0] if parts else ''
        secondary = parts[1] if len(parts) > 1 else ''

        if primary in val_dict:
            prim = val_dict[primary]
            df.loc[index, 'Primary_Email'] = primary
            for k, v in prim.items():
                if k != 'Email':
                    df.loc[index, f'Primary_{k}'] = v

        if secondary in val_dict:
            sec = val_dict[secondary]
            df.loc[index, 'Secondary_Email'] = secondary
            for k, v in sec.items():
                if k != 'Email':
                    df.loc[index, f'Secondary_{k}'] = v

    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    buffer.seek(0)

    return buffer.getvalue(), pd.DataFrame(final_results)

# ==================== UI ====================

uploaded = st.file_uploader("Choose your CSV file", type=["csv"], 
                           help="Multiple emails per cell can be separated by ' * '")

if uploaded:
    try:
        uploaded.seek(0)
        preview = pd.read_csv(uploaded, nrows=10)
        st.dataframe(preview, use_container_width=True)

        email_column = st.selectbox("Select Email Column", preview.columns.tolist())

        if st.button("Start Validation", type="primary"):
            with st.spinner("Processing..."):
                uploaded.seek(0)
                output_csv, live_df = process_csv_with_live_output(uploaded, email_column)

                if output_csv:
                    st.session_state.output_csv = output_csv
                    st.session_state.ready = True
                    st.success("Validation Completed!")

    except Exception as e:
        st.error(f"Error: {str(e)}")

# Download button with reset
if st.session_state.get("ready", False):
    if st.download_button(
        "Download Full Results CSV",
        data=st.session_state.output_csv,
        file_name="validated_results.csv",
        mime="text/csv",
        type="primary"
    ):
        st.session_state.ready = False
        st.rerun()
