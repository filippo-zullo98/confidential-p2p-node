FROM debian:bookworm-slim

# 1. Installazione delle dipendenze di sistema e wget
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libc6-dev \
    python3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 2. Download e installazione automatica di Intel SGX SDK
WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.22.100.3.bin -O sgx_sdk.bin \
    && chmod +x sgx_sdk.bin \
    && echo "yes" | ./sgx_sdk.bin \
    && rm sgx_sdk.bin

# 3. Copia del codice sorgente
WORKDIR /app
COPY . .

# 4. Compilazione del nodo P2P in modalità simulazione
# Usiamo bash per poter usare 'source' e caricare le variabili dell'SDK prima del make
RUN /bin/bash -c "source /opt/intel/sgxsdk/environment && make clean && make SGX_MODE=SIM"

# 5. Esposizione della porta
EXPOSE 8080

# 6. Esecuzione del nodo
# Anche a runtime il nodo avrà bisogno di sapere dove sono le librerie condivise (.so)
CMD ["/bin/bash", "-c", "source /opt/intel/sgxsdk/environment && ./app"]
