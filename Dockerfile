FROM gcc:4.9

RUN apt-get update
RUN apt-get install build-essential libgnutls28-dev libssl-dev -y

RUN mkdir -p /src

COPY . /src

WORKDIR /src

RUN make