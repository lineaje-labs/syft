FROM --platform=linux/amd64 busybox:latest AS builder

RUN mkdir -p /usr/local/bin /usr/local/sbin

# Create fake php and php-fpm binaries with a vendor-suffixed version string embedded.
# The interpreter cataloger scans raw bytes for "X-Powered-By: PHP/<version>", so
# appending that string to any ELF binary is sufficient for the test.
RUN cp /bin/busybox /usr/local/bin/php && \
    printf 'X-Powered-By: PHP/8.1.34-lineaje-01\r\n' >> /usr/local/bin/php

RUN cp /bin/busybox /usr/local/sbin/php-fpm && \
    printf 'X-Powered-By: PHP/8.1.34-lineaje-01\r\n' >> /usr/local/sbin/php-fpm

FROM busybox:latest
COPY --from=builder /usr/local/bin/php  /usr/local/bin/php
COPY --from=builder /usr/local/sbin/php-fpm /usr/local/sbin/php-fpm
