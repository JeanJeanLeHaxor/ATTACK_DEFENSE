FROM wordpress:php7.4-apache

# Install unzip, curl, WP-CLI
RUN apt-get update && apt-get install -y unzip curl less && \
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
    chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

# Remove preinstalled WordPress & install older version
RUN rm -rf /var/www/html/* && \
    wp core download --version=5.2 --allow-root --path=/var/www/html

# Install vulnerable plugins
RUN curl -L -o /tmp/wp-file-upload.zip https://downloads.wordpress.org/plugin/wp-file-upload.4.24.11.zip && \
    unzip /tmp/wp-file-upload.zip -d /var/www/html/wp-content/plugins/
#    curl -L -o /tmp/duplicator.zip https://downloads.wordpress.org/plugin/duplicator.1.2.42.zip && \
#    unzip /tmp/duplicator.zip -d /var/www/html/wp-content/plugins/

# Permissions
RUN chown -R www-data:www-data /var/www/html

COPY setup.sh /setup.sh
RUN chmod +x /setup.sh

ENTRYPOINT ["/setup.sh"]
