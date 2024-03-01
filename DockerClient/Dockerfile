FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git libmagic1 nano
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY client.sh .
RUN git clone https://github.com/lucapa17/toucanstrike
RUN mkdir logs
CMD ["bash", "client.sh"]