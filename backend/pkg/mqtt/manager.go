package mqtt

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Manager wraps an MQTT client and provides helper methods
type Manager struct {
	client    mqtt.Client
	baseTopic string
}

// NewManager creates and connects an MQTT client
func NewManager() (*Manager, error) {
	broker := getenv("MQTT_BROKER", "tcp://localhost:1883")
	username := os.Getenv("MQTT_USERNAME")
	password := os.Getenv("MQTT_PASSWORD")
	baseTopic := getenv("MQTT_BASE_TOPIC", "sealhome")

	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(fmt.Sprintf("sealhome-%d", time.Now().UnixNano()))
	if username != "" {
		opts.SetUsername(username)
	}
	if password != "" {
		opts.SetPassword(password)
	}
	// Optional TLS support if broker is ssl://
	if len(broker) > 6 && broker[:6] == "ssl://" {
		opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	}

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	return &Manager{client: client, baseTopic: baseTopic}, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// PublishCommand publishes a command for a given device/peripheral
func (m *Manager) PublishCommand(deviceID uint, peripheralType string, peripheralIndex int, command string) error {
	topic := fmt.Sprintf("%s/%d/command/%s/%d", m.baseTopic, deviceID, peripheralType, peripheralIndex)
	tok := m.client.Publish(topic, 0, false, command)
	tok.Wait()
	return tok.Error()
}

// SubscribeStates subscribes to state topics and invokes handler
func (m *Manager) SubscribeStates(handler func(deviceID uint, peripheralType string, peripheralIndex int, state string)) error {
	topic := fmt.Sprintf("%s/+/state/+/+", m.baseTopic)
	cb := func(_ mqtt.Client, msg mqtt.Message) {
		// topic: base/<deviceID>/state/<type>/<index>
		var deviceID uint
		var peripheralType string
		var peripheralIndex int
		_, err := fmt.Sscanf(msg.Topic(), m.baseTopic+"/%d/state/%s/%d", &deviceID, &peripheralType, &peripheralIndex)
		if err != nil {
			log.Printf("mqtt: parse topic failed: %v topic=%s", err, msg.Topic())
			return
		}
		handler(deviceID, peripheralType, peripheralIndex, string(msg.Payload()))
	}
	tok := m.client.Subscribe(topic, 0, cb)
	tok.Wait()
	return tok.Error()
}

// Close disconnects the MQTT client
func (m *Manager) Close() {
	if m.client != nil && m.client.IsConnected() {
		m.client.Disconnect(250)
	}
}
