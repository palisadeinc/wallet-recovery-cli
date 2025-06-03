package transport

type PRFKeyGenRequest struct {
	Threshold int `json:"threshold"`
}

type PRFKeystreamRequest struct {
	PlayerCount int    `json:"playerCount"`
	Threshold   int    `json:"threshold"`
	IV          []byte `json:"iv"`
	Length      int    `json:"length"`
}
