# Use PHP with Apache as base image
FROM php:8.0-apache

# Install system dependencies
# Bullseye LTS ended on 2026-08-31; no further official security updates are planned.
# Third-party Extended LTS may support selected packages separately:
# https://www.debian.org/News/2026/20260831
# Restore reliable build downloads using archive.debian.org for bullseye and
# bullseye-updates, plus the fixed 2026-09-01 snapshot for bullseye-security.
# The snapshot avoids live-mirror package 404s and retains final LTS versions.
# It does not extend Debian 11 security support. Any later fix requires changing
# these sources; rebuilding cannot fetch updates beyond the fixed snapshot.
# check-valid-until=no skips only snapshot metadata expiry; signature and checksum
# verification remain enabled. See https://snapshot.debian.org/
RUN sed -i \
        -e 's|deb\.debian\.org/debian |archive.debian.org/debian |g' \
        -e 's|http://deb\.debian\.org/debian-security |[check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260901T000000Z/ |g' \
        /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install curl

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy composer files first for better layer caching
#COPY app/composer.json app/composer.lock ./

# Install PHP dependencies if composer is available
# For now, we'll skip this since there are no dependencies beyond PHP
# RUN composer install --no-dev --optimize-autoloader

# Copy application source code
COPY app/ .

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type d -exec chmod 755 {} \; \
    && find /var/www/html -type f -exec chmod 644 {} \;

# Configure PHP (optional)
RUN echo "expose_php = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "display_errors = Off" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "log_errors = On" >> /usr/local/etc/php/conf.d/security.ini

# Configure Apache (optional)
RUN echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf \
    && echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf \
    && a2enconf security

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/index.php/healthcheck || exit 1

# Expose port 80
EXPOSE 80

# Start Apache in foreground
CMD ["apache2-foreground"]
