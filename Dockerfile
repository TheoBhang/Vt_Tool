FROM python:3.11-slim

WORKDIR /app

COPY . .

EXPOSE 5000

RUN pip install --no-cache-dir -r vt_tool/requirements.txt
RUN pip install --no-cache-dir flask

ENV VT_TOOL_DIR=/app/vt_tool
ENV MISPURL=https://misp-docker-misp-core-1
ENV MISPSSLVERIFY=False

WORKDIR /app/IOC_Dashboard

CMD ["python", "app.py"]
