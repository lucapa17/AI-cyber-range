FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git libmagic1 nano libgomp1
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY main.py .
COPY embernn.py .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]