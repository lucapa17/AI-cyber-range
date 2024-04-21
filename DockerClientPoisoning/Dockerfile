FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git libmagic1 nano libgomp1
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN mkdir logs
COPY features_utils.py .
COPY main.py .
CMD ["python", "main.py"]