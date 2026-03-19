package predictionpipeline

import (
	"context"
	"encoding/json"
	"log"

	"github.com/IBM/sarama"
)

func StartProducing(

	ctx context.Context,
	topicName string,
	apiToProducer <-chan []byte,

) {

	producer := ConfigureProducer()

	log.Println("[PRODUCER INIT]: Starting Producer...")

	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println("ErrFailedToCloseAsyncProducer:", err)
		}
	}()

	log.Println("[PRODUCER INIT]: Starting Success handler...")
	go HandleSuccess(ctx, producer)

	log.Println("[PRODUCER INIT]: Starting Error handler...")
	go HandleError(ctx, producer)

	log.Printf("[PRODUCER]: Waiting for traffic to queue in traffic...\n\n")

	for {
		select {
		case <-ctx.Done():
			log.Println("[PRODUCER]: context cancelled, shutting down main loop")
			return

		case msg, ok := <-apiToProducer:
			if !ok {
				log.Printf("[PRODUCER INFO]: Channel closed. Shutting down listener.")
				return
			}

			var parsedMessage WorkerRequest
			err := json.Unmarshal(msg, &parsedMessage)
			if err != nil {
				log.Printf("[PRODUCER ERROR]: Unable to forward to topic. Failed to unmarshall: %v, RawMessage: %s", err, string(msg))
				continue
			}

			kafkaMsg := &sarama.ProducerMessage{
				Topic: topicName,
				Value: sarama.ByteEncoder(msg),
				Key:   sarama.StringEncoder(parsedMessage.ClientRequestHost),
			}

			select {
			case producer.Input() <- kafkaMsg:
				log.Printf("[PRODUCER SUCCESS]: Queued message with key %s to topic %s", parsedMessage.ClientRequestHost, topicName)
			case <-ctx.Done():
				log.Println("[PRODUCER]: context cancelled while queuing message")
				return
			}
		}
	}
}
