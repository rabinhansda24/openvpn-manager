FROM alpine:3.18

# Install OpenVPN and dependencies
RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    iptables \
    openssl \
    bash \
    curl \
    && mkdir -p /etc/openvpn/easy-rsa

# Copy Easy-RSA to the container
RUN cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/

# Create necessary directories
RUN mkdir -p /var/log/openvpn \
    && mkdir -p /etc/openvpn/ccd \
    && mkdir -p /etc/openvpn/clients

# Set working directory
WORKDIR /etc/openvpn

# Copy initialization script
COPY init-container.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-container.sh

# Expose OpenVPN port
EXPOSE 1194/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD pgrep openvpn || exit 1

# Default command
CMD ["/usr/local/bin/init-container.sh"]