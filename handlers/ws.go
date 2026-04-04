package handlers

import (
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func WSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			if isExpectedWebSocketClose(err) {
				break
			}
			log.Println("Read error:", err)
			break
		}
		log.Printf("收到客户端消息: %s", message)

		reply := []byte("服务端已收到: " + string(message))
		if err := conn.WriteMessage(mt, reply); err != nil {
			log.Println("Write error:", err)
			break
		}
	}
}

func isExpectedWebSocketClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived)
}
