FROM alpine:3.20

RUN apk add --no-cache curl unzip ca-certificates \
  && curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
  && unzip /tmp/xray.zip xray -d /usr/local/bin/ \
  && chmod +x /usr/local/bin/xray \
  && rm -f /tmp/xray.zip

COPY config.json /etc/xray/config.json

EXPOSE 7860
CMD ["xray", "run", "-c", "/etc/xray/config.json"]
