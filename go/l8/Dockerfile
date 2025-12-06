FROM saichler/builder:latest AS build

COPY main.go /home/src/github.com/saichler/build/main.go
COPY .netrc /root/.netrc

RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN go build -o oweb

FROM saichler/business-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/oweb /home/run/oweb
COPY ./web /home/run/web

ENTRYPOINT ["/home/run/oweb"]