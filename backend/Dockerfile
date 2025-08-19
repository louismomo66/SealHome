# Start from the official Golang image for build stage
FROM golang:1.23 as builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/web

# Use a minimal base image for the final stage
FROM alpine:latest
WORKDIR /root/

# Copy the built binary from the builder stage
COPY --from=builder /app/server .

# Expose the web server port
EXPOSE 9004

# Set environment variable for DSN (can be overridden at runtime)
ENV DSN=""

# Command to run the server
CMD ["./server"] 