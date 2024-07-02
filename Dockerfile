FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install apt-transport-https ca-certificates gnupg curl python3 python3-pip -y

RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" >> /etc/apt/sources.list.d/google-cloud-sdk.list

RUN apt-get update -y && apt-get install google-cloud-cli -y

WORKDIR /usr/src/gcpwn

ADD . ./
RUN apt-get install python3.12-venv -y
RUN python3 -m venv venv
RUN  ./venv/bin/pip install -r /usr/src/gcpwn/requirements.txt

ENTRYPOINT ["/usr/src/gcpwn/venv/bin/python3", "/usr/src/gcpwn/main.py"]

# RUN WITH
# docker run -v $(echo pwd):/usr/src/gcpwn -it gcpwn 