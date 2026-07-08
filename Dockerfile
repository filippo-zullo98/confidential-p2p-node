FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libc6-dev \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY sgxsdk /opt/intel/sgxsdk
ENV SGX_SDK=/opt/intel/sgxsdk

# ECCO LA CORREZIONE: Indichiamo al linker dinamico di Linux dove trovare le librerie SGX a runtime
ENV LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64

WORKDIR /app

COPY . .

RUN rm -rf sgxsdk
RUN make clean && make SGX_MODE=SIM

EXPOSE 8080
ENTRYPOINT ["./app"]
