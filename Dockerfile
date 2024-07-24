FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install apt-transport-https ca-certificates gnupg curl python3 python3-venv -y

RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" >> /etc/apt/sources.list.d/google-cloud-sdk.list

RUN apt-get update -y &&  apt-get install google-cloud-cli -y

WORKDIR /usr/src/gcpwn

COPY . ./
RUN python3 -m venv venv
RUN  ./venv/bin/pip install -r /usr/src/gcpwn/requirements.txt

ENTRYPOINT ["/bin/bash","-c","source /usr/src/gcpwn/venv/bin/activate && exec /bin/bash"]
