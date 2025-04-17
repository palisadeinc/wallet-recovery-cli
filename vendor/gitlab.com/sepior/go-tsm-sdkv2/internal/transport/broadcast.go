package transport

type BroadcastRequest struct {
	Message []byte `json:"message"`
}

type BroadcastResponse struct {
	Messages map[int][]byte `json:"messages"`
}
