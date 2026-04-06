#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import csv
import time
from datetime import datetime
from tqdm import tqdm

def save_to_report(data):
    with open('privacy_audit_report.csv', 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

def get_rdap_info(url):
    try:
        domain = url.split('//')[-1].split('/')[0].replace('www.', '')
        rdap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(rdap_url, timeout=3)
        registrar = "Unknown"
        if response.status_code == 200:
            data = response.json()
            for entity in data.get('entities', []):
                roles = entity.get('roles', [])
                name = "Unknown"
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    for entry in vcard[1]:
                        if entry[0] == 'fn' and entry[3].strip():
                            name = entry[3].strip()
                            break
                if name == "Unknown":
                    for sub in entity.get('entities', []):
                        sub_vcard = sub.get('vcardArray', [])
                        if len(sub_vcard) > 1:
                            for entry in sub_vcard[1]:
                                if entry[0] == 'fn' and entry[3].strip():
                                    name = entry[3].strip()
                                    break
                if 'registrar' in roles:
                    registrar = name
                    break  # no need to keep looping once found
        return registrar
    except:
        return "Lookup Failed"

def audit_site(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://www.google.com/'
    }
    registrar = get_rdap_info(url)
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text_lower = response.text.lower()
            all_links = soup.find_all('a', href=True)
            all_link_hrefs = [a.get('href', '').lower() for a in all_links]
            all_link_text = [a.text.lower() for a in all_links]

            # --- CCPA/CPRA (California) ---
            # Legally requires: visible "Do Not Sell or Share" link, not just mentioned
            ccpa_dns_link = any('do not sell' in t or 'do not share' in t for t in all_link_text)
            ccpa_dns_href = any('do-not-sell' in h or 'do-not-share' in h or 'optout' in h for h in all_link_hrefs)
            ccpa_limit_sensitive = any(k in text_lower for k in ['limit the use of my sensitive', 'limit my sensitive'])
            ccpa_pass = ccpa_dns_link or ccpa_dns_href or ccpa_limit_sensitive

            # --- GDPR (EU/UK) ---
            # Legally requires: cookie consent banner, DPO contact, right to erasure mention
            gdpr_cookie_banner = any(k in text_lower for k in ['accept cookies', 'cookie consent', 'manage cookies', 'cookie preferences', 'we use cookies'])
            gdpr_dpo_contact = 'dpo@' in text_lower or 'data protection officer' in text_lower
            gdpr_erasure = any(k in text_lower for k in ['right to erasure', 'right to be forgotten'])
            gdpr_supervisory = 'supervisory authority' in text_lower
            gdpr_pass = gdpr_cookie_banner and (gdpr_dpo_contact or gdpr_erasure or gdpr_supervisory)

            # --- PIPEDA (Canada) ---
            # Legally requires: named privacy officer, consent mechanism, access/correction rights
            pipeda_officer = any(k in text_lower for k in ['privacy officer', 'chief privacy', 'office of the privacy commissioner'])
            pipeda_consent = any(k in text_lower for k in ['withdraw consent', 'withhold consent', 'consent to collect'])
            pipeda_access = any(k in text_lower for k in ['access your information', 'access your personal', 'correct your information'])
            pipeda_pass = pipeda_officer or (pipeda_consent and pipeda_access)

            # --- HIPAA (Healthcare) ---
            # Legally requires: Notice of Privacy Practices (NPP), PHI mention, patient rights
            hipaa_npp = any(k in text_lower for k in ['notice of privacy practices', 'npp', 'notice of privacy'])
            hipaa_phi = any(k in text_lower for k in ['protected health information', 'phi'])
            hipaa_rights = any(k in text_lower for k in ['patient rights', 'right to access your health', 'health information portability'])
            hipaa_pass = hipaa_npp or (hipaa_phi and hipaa_rights)

            # --- COPPA (Children) ---
            # Legally requires: parental consent mechanism, no collection from under 13 without consent
            coppa_age_gate = any(k in text_lower for k in ['under 13', 'age 13', 'not directed to children'])
            coppa_parental = any(k in text_lower for k in ['verifiable parental consent', 'parental consent', 'parent or guardian'])
            coppa_collection = any(k in text_lower for k in ['do not knowingly collect', 'not knowingly collect'])
            coppa_pass = coppa_age_gate and (coppa_parental or coppa_collection)

            # --- VCDPA (Virginia) ---
            # Legally requires: opt out of sale/targeted ads, right to appeal, data rights
            vcdpa_optout = any(k in text_lower for k in ['opt out of the sale', 'opt out of targeted', 'opt out of profiling'])
            vcdpa_appeal = 'right to appeal' in text_lower
            vcdpa_rights = any(k in text_lower for k in ['virginia consumer data', 'vcdpa', 'virginia residents'])
            vcdpa_pass = vcdpa_rights and (vcdpa_optout or vcdpa_appeal)

            # --- Global/General ---
            # Baseline: must have a linked privacy policy and terms of service
            has_privacy_link = any('privacy' in href for href in all_link_hrefs)
            has_tos_link = any('terms' in href or 'tos' in href for href in all_link_hrefs)
            global_pass = has_privacy_link and has_tos_link

            # --- Build findings ---
            law_results = {
                'CCPA/CPRA (California)': ccpa_pass,
                'GDPR (EU/UK)': gdpr_pass,
                'PIPEDA (Canada)': pipeda_pass,
                'HIPAA (Healthcare)': hipaa_pass,
                'COPPA (Children)': coppa_pass,
                'VCDPA (Virginia)': vcdpa_pass,
                'Global/General': global_pass
            }
            findings = [law for law, passed in law_results.items() if passed]
            status = 'PASS' if findings else 'FLAG'
            result_str = ", ".join(findings) if findings else "No specific jurisdictional markers"

            # --- Hard compliance signals ---
            has_cookie_banner = gdpr_cookie_banner
            has_dns_link = ccpa_dns_link or ccpa_dns_href
            has_dpo_contact = gdpr_dpo_contact

            save_to_report([url, status, result_str, registrar,
                has_privacy_link, has_tos_link, has_cookie_banner, has_dns_link, has_dpo_contact,
                ccpa_pass, gdpr_pass, pipeda_pass, hipaa_pass, coppa_pass, vcdpa_pass, global_pass,
                datetime.now().strftime("%Y-%m-%d %H:%M")])

        elif response.status_code == 403:
            save_to_report([url, "WAF_BLOCK", "ACCESS DENIED (403)", registrar,
                '', '', '', '', '',
                '', '', '', '', '', '', '',
                datetime.now().strftime("%Y-%m-%d %H:%M")])
        else:
            save_to_report([url, "HTTP_ERROR", f"Status: {response.status_code}", registrar,
                            '', '', '', '', '',
                            '', '', '', '', '', '', '',
                            datetime.now().strftime("%Y-%m-%d %H:%M")])

    except requests.exceptions.Timeout:
        save_to_report([url, "TIMEOUT", "Server unresponsive", registrar,
                        '', '', '', '', '',
                        '', '', '', '', '', '', '',
                        datetime.now().strftime("%Y-%m-%d %H:%M")])
    except requests.exceptions.ConnectionError:
        save_to_report([url, "DNS_ERROR", "Domain could not be resolved", registrar,
                        '', '', '', '', '',
                        '', '', '', '', '', '', '',
                        datetime.now().strftime("%Y-%m-%d %H:%M")])
    except Exception:
        save_to_report([url, "ERROR", "Connection Timeout/Failed", registrar,
                        '', '', '', '', '',
                        '', '', '', '', '', '', '',
                        datetime.now().strftime("%Y-%m-%d %H:%M")])
def main():
    with open('privacy_audit_report.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([ "URL", "Status", "Findings", "Registrar",
    "Has Privacy Link", "Has TOS Link", "Has Cookie Banner", "Has DNS Link", "Has DPO Contact",
    "CCPA/CPRA Pass", "GDPR Pass", "PIPEDA Pass", "HIPAA Pass", "COPPA Pass", "VCDPA Pass", "Global Pass",
    "Audit Timestamp"
])
    try:
        with open('target_urls.txt', 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"\n -- Starting Audit on {len(urls)} domains --\n")
        for line in tqdm(urls, desc="Auditing", ncols=60):
            target = line if line.startswith('http') else f"https://{line}"
            audit_site(target)
            time.sleep(0.1)

        print("\nAudit complete. Results saved in 'privacy_audit_report.csv'")
    except FileNotFoundError:
        print("Error: target_urls.txt not found")

if __name__ == "__main__":
    main()