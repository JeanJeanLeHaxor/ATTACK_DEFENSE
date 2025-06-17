#!/bin/bash

# Start Apache in background
docker-entrypoint.sh apache2 &

# Wait for database and WordPress files to initialize
sleep 20

cd /var/www/html

# Install WordPress
wp core install --url="http://localhost:8080" \
    --title="VulnWP Lab" \
    --admin_user=admin \
    --admin_password=admin123 \
    --admin_email=admin@example.com \
    --skip-email \
    --allow-root

# Create brute-forceable user
#wp user create testuser test@example.com --user_pass=123456 --role=subscriber --allow-root

# Activate vulnerable plugins
wp plugin activate wp-file-upload --allow-root
#wp plugin activate simple-301-redirects-addon-bulk-uploader duplicator --allow-root

exec apache2-foreground
