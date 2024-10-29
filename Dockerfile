FROM golang:alpine AS builder

ENV GO111MODULE=on \
    GOPROXY=https://goproxy.io \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

COPY . .

RUN go build -o enroll .

FROM scratch

COPY --from=builder /build/enroll .

CMD [ "./enroll" ]