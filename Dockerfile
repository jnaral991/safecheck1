FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# allow big files in the scanner, and download the virus database now
RUN sed -i '/^MaxFileSize/d;/^MaxScanSize/d;/^StreamMaxLength/d' /etc/clamav/clamd.conf \
 && printf 'MaxFileSize 4000M\nMaxScanSize 4000M\nStreamMaxLength 4000M\n' >> /etc/clamav/clamd.conf \
 && (freshclam || true)
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN chmod +x start.sh
CMD ["./start.sh"]
