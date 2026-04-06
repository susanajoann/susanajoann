This python script scrapes websites on the target_urls.txt file and checks them for certain keywords associated with
different data privacy laws and policies. It complies the information into privacy_audit_report.csv! 

See below for thepolicies checked and key words:

- CCPA (California) : ["Do not sell", "Optout"] as a link OR ["Limit the use of my sensitive", "limit my sensitive"] anywhere in text
    - visible "Do Not Sell or Share" link, not just mentioned
      
- GDPR (UK/EU) : ["dpo@", "data protection officer", "right to erasure", "right to be forgotten", "supervisory authority"] as a link
    - cookie consent banner, DPO contact, right to erasure mention
      
- PIPEDA (Canada) : ["privacy officer", "cheif privacy", "office of the privacy commissioner"] OR (["withdraw consent", "withhold consent", "consent to collect"] AND ["access your information", "access your personal", "correct your information"])
    -  named privacy officer, consent mechanism, access/correction rights
       
- HIPPA (Healthcare) : ["notice of privacy practices", "npp", "notice of privacy", "protected health information", "phi", "patient rights", "right to access your health", "health information portability"]
    -  notice of Privacy Practices (NPP), PHI mention, patient rights
       
- COPPA : ["under 13", "age 13", "not directed to children"] AND (["verifiable parental consent", "parental consent", "parent or guardian"] OR  ["do not knowingly collect", "not knowingly collect"])
    - parental consent mechanism, no collection from under 13 without consent
      
- VCDPA (Virginia) : ["Virginia consumer data", "vcdpa", "virginia residents"] AND (["opt out of the sale", "opt out of targeted", "opt out of profiling"] OR ["right to appeal"]
    - opt out of sale/targeted ads, right to appeal, data rights
    
- General : ["privacy"] in links AND ["terms", "tos"] in links
    - linked privacy policy and terms of service
