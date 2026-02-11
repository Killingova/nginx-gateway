FROM nginx:stable-alpine

RUN rm -f /etc/nginx/conf.d/default.conf \
 && mkdir -p /etc/nginx/api_conf.d

COPY nginx.conf /etc/nginx/nginx.conf
COPY api_gateway.conf /etc/nginx/api_gateway.conf
COPY api_conf.d/ /etc/nginx/api_conf.d/
COPY conf.d/ /etc/nginx/conf.d/
