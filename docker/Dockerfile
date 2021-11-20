FROM python:3.8-slim

COPY src/app.py /src/app.py
COPY src/queryfilter.py /src/queryfilter.py

RUN mkdir -p /var/log/pgrelay/ /etc/pgrelay/ && \
    pip install PyYAML

WORKDIR /src

CMD ["/usr/local/bin/python", "-u", "src.py"]
