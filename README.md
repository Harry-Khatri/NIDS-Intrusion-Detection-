NIDS/
├── custom-rules/           # Custom Suricata or NIDS detection rules
├── extract_osq/            # Scripts/tools for extracting osquery data
├── NIDS/                   # Core detection logic and modules
├── osquery/                # osquery binaries and config
├── reports/                # Generated reports and logs
├── response_playbooks/     # Automated response scripts/playbooks
├── scripts/                # Python/Bash scripts (automation, alert, response)
├── threat-intel/           # Threat intelligence enrichment scripts/data
├── .gitattributes
├── .gitignore
├── README.md               # Project documentation (this file)
├── requirements.txt        # Python dependencies (if used)


git clone https://github.com/<your-username>/<your-repo>.git
cd NIDS

pip install -r requirements.txt


#for installation or importing the large binaries from github
git lfs install
git lfs track "osquery/osqueryd"


#for automating the alerts
python scripts/send_alert_email.sh

#For email report generation
python scripts/report_to_pdf.py
