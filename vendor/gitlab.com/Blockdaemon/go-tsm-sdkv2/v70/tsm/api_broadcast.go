package tsm

import (
	"context"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/transport"
	"net/http"
)

// BroadcastAPI contains methods for broadcasting of arbitrary data.
//
// For example, this can be used to broadcast the partial signatures obtained by ECDSAAPI.Sign().
type BroadcastAPI interface {
	// SimpleBroadcast lets each player broadcast an arbitrary message to all participating players.
	//
	// The default maximum size of the message is 65536 bytes, but this can be changed in the MPC node configuration.
	//
	// CAVEAT: This broadcast only takes one round, but lacks some properties: A malicious sender may send different
	// messages to each of the other nodes. And a malicious MPC node may take the message it receives from another MPC
	// node, and use it as its own message for another player.
	//
	// Output:
	//   - messages: A mapping from player ID to the message sent by that player.
	SimpleBroadcast(ctx context.Context, sessionConfig *SessionConfig, message []byte) (messages map[int][]byte, err error)

	// AdvancedBroadcast lets each player broadcast an arbitrary message to all participating players.
	//
	// The default maximum size of the message is 65536 bytes, but this can be changed in the MPC node configuration.
	//
	// This broadcast takes two rounds. In the first round, each MPC node sends a cryptographic commitment
	// of its message and its own player ID, which identifies the sender, to all MPC nodes. In the second round, each
	// MPC node sends the opening of its commitment to all other MPC nodes, along with the commitments received by the
	// other MPC nodes in the first round. Each MPC node checks that all commitments are valid and that all nodes agree
	// on the messages received and that the sender IDs are correct.
	// These steps ensure
	//
	//   - Consistency. Any two MPC nodes that does not abort, will agree on the message broadcast
	//     by another MPC node, even if that node was malicious.
	//   - Message independence. The commitments ensure that a malicious MPC node cannot let its own message depend on
	//     the messages sent by the other MPC nodes.
	//
	// Note: This is not a "full" broadcast. While consistent, it is not reliable in the sense that it does not prevent
	// a malicious MPC node to cause some MPC nodes to abort while others succeed.
	//
	// Output:
	//   - messages: A mapping from player ID to the message sent by that player.
	AdvancedBroadcast(ctx context.Context, sessionConfig *SessionConfig, message []byte) (messages map[int][]byte, err error)
}

type broadcastService struct {
	*node
}

// SimpleBroadcast sends a single message to all players and receives messages from all players. There is no guarantee
// that all players receive the same set of messages, and a malicious player might choose his message based on the
// messages of the honest players.
func (b *broadcastService) SimpleBroadcast(ctx context.Context, sessionConfig *SessionConfig, message []byte) (map[int][]byte, error) {
	return b.broadcasts(ctx, sessionConfig, "simple", message)
}

// AdvancedBroadcast sends a single message to all players and receives messages from all players. All players are
// guaranteed to receive the same set of messages, and a player cannot see the messages of other players before deciding
// on which message to send. This requires one more round of communication compared to SimpleBroadcast.
func (b *broadcastService) AdvancedBroadcast(ctx context.Context, sessionConfig *SessionConfig, message []byte) (map[int][]byte, error) {
	return b.broadcasts(ctx, sessionConfig, "advanced", message)
}

func (b *broadcastService) broadcasts(ctx context.Context, sessionConfig *SessionConfig, broadcastType string, message []byte) (map[int][]byte, error) {
	res, err := b.call(ctx, http.MethodPost, fmt.Sprintf("/broadcast/%s", broadcastType), sessionConfig, b.sendAuthenticatedRequest,
		func() interface{} {
			return transport.BroadcastRequest{
				Message: message,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.BroadcastResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}
	return jsonResponse.Messages, nil
}
