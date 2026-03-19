package predictionpipeline

import (
	"context"
	"log"

	"github.com/IBM/sarama"
)

/*
goroutine for handling successes

NOTE:
Successes is the success output channel back to the user when Return.Successes is enabled.
If Return.Successes is true, you MUST read from this channel or the Producer will deadlock.
It is suggested that you send and read messages together in a single select statement.

By using separate goroutines to handle success and error cases, we ensure that the producer’s channels
(Successes() and Errors()) are always being consumed, which prevents deadlocks.
*/
func HandleSuccess(ctx context.Context, producer sarama.AsyncProducer) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-producer.Successes():
			if !ok {
				return
			}
			log.Printf("[PRODUCER SUCCESS]: Message sent to partition %d at offset %d\n", msg.Partition, msg.Offset)
		}
	}
}

/*
goroutine for handling errors

NOTE:
Errors is the error output channel back to the user. You MUST read from this channel or
the Producer WILL deadlock when the channel is full. Alternatively, you can set
Producer.Return.Errors in your config to false, which prevents errors to be returned.

By using separate goroutines to handle success and error cases, we ensure that the producer’s channels
(Successes() and Errors()) are always being consumed, which prevents deadlocks.
*/
func HandleError(ctx context.Context, producer sarama.AsyncProducer) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-producer.Errors():
			log.Printf("[PRODUCER ERROR]: Failed to send message %v", err)
			/*
				when sarama's async producer exceeds retries, the message is considered failed
				and is sent here, we can do with it what we want. I suspect we should log it
				and try to figure out what caused it to fail as it needs to fail multiple times
				as we have configred sarama's retry to try 10 times.
			*/
			if !ok {
				// channel is closed, producer is done
				return
			}
		}
	}
}
