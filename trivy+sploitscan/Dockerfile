FROM python:3.12-slim-bullseye

WORKDIR /scan

RUN apt-get update -qq && apt-get install -y -qq wget git tar && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/antonbombov/trivy

RUN git clone https://github.com/antonbombov/SploitScan /sploitscan

RUN pip install --no-cache-dir -r /sploitscan/requirements.txt

RUN mkdir -p /scan/trivy/trivy+sploitscan/cache
RUN mkdir -p /scan/trivy/trivy+sploitscan/input
RUN mkdir -p /scan/trivy/trivy+sploitscan/results

RUN echo '{ \
  "sploitscan_path": "/sploitscan/sploitscan.py", \
  "scan_directory": "/scan/trivy/trivy+sploitscan/input/", \
  "cache_directory": "/scan/trivy/trivy+sploitscan/cache/", \
  "output_directory": "/scan/trivy/trivy+sploitscan/results", \
  "cache_max_days": 30, \
  "max_workers": null, \
  "timeout": 90, \
  "project_version": "0.4.0" \
}' > /scan/trivy/trivy+sploitscan/config.json

RUN echo '#!/bin/bash\n\
cd /scan/trivy/trivy+sploitscan\n\
python -u main.py\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]