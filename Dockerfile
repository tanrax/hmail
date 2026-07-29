FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY hmtp/ hmtp/
RUN pip install --no-cache-dir .

ENV HMTP_HOME=/data
ENV HMTP_HOST=0.0.0.0

ENTRYPOINT ["hmtp"]
CMD ["serve", "8025"]
