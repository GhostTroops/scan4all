FROM golang:1.18.1-alpine AS build-env
RUN go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

FROM alpine:latest
COPY --from=build-env /go/bin/mapcidr /usr/local/bin/mapcidr
ENTRYPOINT ["mapcidr"]
