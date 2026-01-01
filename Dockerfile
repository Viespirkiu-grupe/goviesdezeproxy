# Stage 1: Build Go binary
FROM golang:1.25.5-bookworm AS builder

WORKDIR /temp

COPY go.mod go.sum ./
RUN go mod download

# Copy the full folder structure
COPY . .

RUN CGO_ENABLED=1 go build -o app .

# Final image with Debian slim + headless LibreOffice
FROM debian:bookworm-slim

WORKDIR /work

# Install LibreOffice headless + minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libreoffice-core \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    libreoffice-common \
    fonts-dejavu-core \
    fonts-dejavu-extra \
    fonts-liberation \
    fonts-noto \
    libheif-dev \
    imagemagick \
    libemail-outlook-message-perl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /temp/app /app

RUN mv /etc/ImageMagick-6/policy.xml /etc/ImageMagick-6/policy.xml.bak

ENTRYPOINT ["/app"]
