package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	api "wpsec/internal/api"
	prediction_pipeline "wpsec/internal/prediction-pipeline"
)

/*
	how it works:

	API listens for inbound "log" requests.
	It passes the bytes received into a channel that the
	producer is listening to. The producer then writes
	this into the kafka topic

	todo: host endpoint for verifying solutions, serve challenge page
	itself to users from plugin, and finally, consume from prediction pipeline
	once Anton sets up something dedicated & POST to the plugin (wp server) otherwise I will need
	to maintain a db of plugin customers only and consume from the topic ignoring anything
	that isnt a paying customer
*/

func main() {

	allowedOriginsString := os.Getenv("ALLOWED_ORIGINS_COMMA_SEPARATED_VALUES")
	if allowedOriginsString == "" {
		log.Fatalf("Expected %s to be non empty, got ''", allowedOriginsString)
	}
	ALLOWED_ORIGINS_COMMA_SEPARATED_VALUES := strings.Split(allowedOriginsString, ",")

	SERVER_ADDRESS := os.Getenv("SERVER_ADDRESS")
	if SERVER_ADDRESS == "" {
		log.Fatalf("Expected %s to be non empty, got ''", allowedOriginsString)
	}

	PRODUCER_TOPIC_NAME := os.Getenv("PRODUCER_TOPIC_NAME")
	if PRODUCER_TOPIC_NAME == "" {
		log.Fatalf("Expected %s to be non empty, got ''", allowedOriginsString)
	}

	stripeSecretKey := os.Getenv("STRIPE_SECRET_KEY")
	if stripeSecretKey == "" {
		log.Fatal("missing STRIPE_SECRET_KEY")
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//-----------------------------------
	//server & logic
	//-----------------------------------

	var apiReady sync.WaitGroup
	apiReady.Add(1)

	//API writes to this channel when a request is received
	//the bytes are transmitted to the producer who will parse and
	//inform the kafka topic.
	apiToProducer := make(chan []byte)

	go api.StartAPI(
		ALLOWED_ORIGINS_COMMA_SEPARATED_VALUES,
		&apiReady,
		apiToProducer,
		ctx,
		SERVER_ADDRESS,
		stripeSecretKey,
	)

	apiReady.Wait()

	go prediction_pipeline.StartProducing(
		ctx,
		PRODUCER_TOPIC_NAME,
		apiToProducer,
	)

	<-stopChan
	cancel()
	log.Printf("Shutdown.")
}
