FROM ghcr.io/radiosilence/nano-web:latest

LABEL org.opencontainers.image.source="https://github.com/radiosilence/sbr" \
  org.opencontainers.image.url="https://sbr.blit.cc" \
  org.opencontainers.image.title="sbr-site" \
  org.opencontainers.image.description="sbr.blit.cc"

COPY public /public
ENV PORT=3000
EXPOSE 3000
