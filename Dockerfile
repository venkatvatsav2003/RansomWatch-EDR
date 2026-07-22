FROM python:3.11-slim

WORKDIR /edr

RUN pip install --no-cache-dir pyyaml

COPY . /edr
RUN mkdir -p honeypot logs

ENTRYPOINT ["./edr.sh"]
CMD ["monitor"]
