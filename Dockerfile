FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY requirements.txt .

RUN pip install  --no-cache-dir -r requirements.txt

COPY src ./src

RUN pip install --no-cache-dir .

EXPOSE 5000

CMD ["python", "src/netsentinel/app.py"]