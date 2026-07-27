FROM python:3.13-slim

RUN pip install --no-cache-dir flask httpx cryptography waitress

WORKDIR /app
COPY hmtp.py .

ENV HMTP_HOME=/data
ENV HMTP_HOST=0.0.0.0

ENTRYPOINT ["python", "hmtp.py"]
CMD ["serve", "8025"]
