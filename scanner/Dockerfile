FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py", "--target", "brokencheckout", "--output", "/app/output"]
