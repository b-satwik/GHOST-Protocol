FROM python:3.11-slim

WORKDIR /app

# Create persistent data directory for SQLite database
RUN mkdir -p /app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY db.py app.py ./

EXPOSE 8080

CMD ["python", "app.py"]
