package mq

// 预留消息队列接口；需要时替换为 RabbitMQ / Kafka 等实现

type Publisher interface {
	Publish(topic string, payload []byte) error
}

type Subscriber interface {
	Subscribe(topic string, handler func([]byte) error) error
}

type Noop struct{}

func (Noop) Publish(topic string, payload []byte) error               { return nil }
func (Noop) Subscribe(topic string, handler func([]byte) error) error { return nil }
