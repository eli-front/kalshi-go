package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	// use the package name client
	"github.com/eli-front/kalshi/client"
)

const IsDemoMode = true

func main() {
	// load .env
	envFileName := ".demo.env"
	clientEnv := client.EnvironmentDemo

	if !IsDemoMode {
		envFileName = ".prod.env"
		clientEnv = client.EnvironmentProd
	}
	if err := godotenv.Load(envFileName); err != nil {
		log.Fatal("error loading .env file:", err)
	}

	apiID := os.Getenv("KALSHI_API_ID")
	privateKeyPEM := os.Getenv("KALSHI_API_SECRET")
	if apiID == "" || privateKeyPEM == "" {
		log.Fatal("missing KALSHI_API_ID or KALSHI_API_SECRET in environment")
	}

	// parse RSA private key
	priv, err := client.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		log.Fatal("failed to parse private key:", err)
	}

	// build HTTP client, use demo or prod
	httpClient, err := client.NewKalshiHTTPClient(apiID, priv, clientEnv)
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
