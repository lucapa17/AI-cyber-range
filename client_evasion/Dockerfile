FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git libmagic1 nano dos2unix cmake gcc g++
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN git clone https://github.com/lucapa17/toucanstrike
RUN mkdir logs
COPY client_evasion.sh .
RUN dos2unix client_evasion.sh
CMD ["bash", "client_evasion.sh"]