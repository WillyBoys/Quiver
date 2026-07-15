FROM alpine:3.20
RUN apk add --no-cache curl jq
COPY init.sh /init.sh
RUN chmod +x /init.sh
CMD ["/init.sh"]
