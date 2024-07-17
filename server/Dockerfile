FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git libmagic1 nano libgomp1 cmake gcc g++
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN git clone -b 0.9.0 https://github.com/lief-project/lief.git
RUN mkdir -p /app/lief/build
ENV PYTHON_VERSION=3.9
RUN cmake -S /app/lief -B /app/lief/build -DPYTHON_VERSION=3.9 \
    && cmake --build /app/lief/build --target pyLIEF \
    && pip install /app/lief/build/api/python
COPY download_extract_ember_dataset.py .
RUN python download_extract_ember_dataset.py
COPY server.py .
COPY embernn.py .
EXPOSE 8000
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]