package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	// use the package name client
	"github.com/eli-front/kalshi-go"
)

func main() {
	// Parse command line flags
	envFile := flag.String("env", ".env", "Path to environment file")
	flag.Parse()

	// Load environment file
	if err := godotenv.Load(*envFile); err != nil {
		log.Fatal("error loading .env file:", err)
	}

	// choose environment based on DEMO env var
	clientEnv := kalshi.EnvironmentProd
	if os.Getenv("DEMO") == "true" {
		clientEnv = kalshi.EnvironmentDemo
	}

	apiID := os.Getenv("KALSHI_API_ID")
	privateKeyPEM := os.Getenv("KALSHI_API_SECRET")
	if apiID == "" || privateKeyPEM == "" {
		log.Fatal("missing KALSHI_API_ID or KALSHI_API_SECRET in environment")
	}

	// parse RSA private key
	priv, err := kalshi.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		log.Fatal("failed to parse private key:", err)
	}

	// build HTTP client, use demo or prod
	httpClient, err := kalshi.NewKalshiHTTPClient(apiID, priv, clientEnv)
	if err != nil {
		log.Fatal("failed to create client:", err)
	}

	// simple read test
	ctx := context.Background()
	balance, err := httpClient.GetBalance(ctx)
	if err != nil {
		log.Fatal("failed to get balance:", err)
	}

	fmt.Println("Balance response:", balance)
}
