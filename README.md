# Kalshi Go Client

A Go client library for seamless integration with the Kalshi prediction markets API.

## Installation

```bash
go get github.com/eli-front/kalshi-go
```

## Usage

Import the package in your Go code:

```go
import "github.com/eli-front/kalshi-go"
```

## Environment Setup

1. Create your environment file by copying the example:
   ```bash
   cp .env.example .env
   ```

2. Fill in your API key and secret in the `.env` file.
   - If you're using demo credentials, set `DEMO=true` to avoid authentication errors (401).

## Examples

Run the balance example:
```bash
go run ./examples/balance
```

The examples support command-line flags:
```bash
# Specify a custom environment file
go run ./examples/balance --env .custom.env
```

