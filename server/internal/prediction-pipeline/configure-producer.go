package predictionpipeline

import (
	"log"
	"time"
	tlsconfig "wpsec/internal/tls-config"

	"github.com/IBM/sarama"
)

func ConfigureProducer() sarama.AsyncProducer {
	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0

	//setup TLS using the tlsconfig package
	tlsConfig := tlsconfig.CreateKafkaTLSConfig()
	config.Net.TLS.Enable = true
	config.Net.TLS.Config = tlsConfig

	//configs
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Producer.Retry.Max = 10
	config.Producer.Retry.Backoff = 100 * time.Millisecond
	config.ClientID = "prediction-pipeline-producer"
	config.ChannelBufferSize = 256

	bootstrapServers := []string{
		"kafkadev0.prod.deflect.network:9094",
		"kafkadev1.prod.deflect.network:9094",
		"kafkadev2.prod.deflect.network:9094",
	}

	producer, err := sarama.NewAsyncProducer(bootstrapServers, config)
	if err != nil {
		log.Fatal("Failed to start Sarama producer:", err)
	}

	return producer
}
