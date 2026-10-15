FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY warden ./warden
COPY contracts ./contracts
COPY injection ./injection
RUN pip install --no-cache-dir .
COPY config ./config
EXPOSE 8000
CMD ["uvicorn", "warden.main:app", "--host", "0.0.0.0", "--port", "8000"]
