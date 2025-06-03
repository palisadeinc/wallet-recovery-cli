package secretshare

type XORBedozaShare struct {
	KeyShare []byte         // The player's own xor key share
	MACKeys  map[int][]byte // The keys used to produce a tag on each of the other players' key share
	MACTags  map[int][]byte // A tag on the player's own key share for each of the other players
}
