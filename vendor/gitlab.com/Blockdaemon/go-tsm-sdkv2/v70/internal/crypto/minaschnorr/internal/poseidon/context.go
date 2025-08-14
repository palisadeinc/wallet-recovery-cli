package poseidon

import (
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"sync"
)

var (
	once     sync.Once
	contexts []*context
)

type context struct {
	state                                         []ec.Scalar
	absorbed, spongeWidth, spongeRate, fullRounds int
	sBox                                          sBox
	pType                                         Permutation
	spongeIv                                      [][]ec.Scalar
	roundKeys                                     [][]ec.Scalar
	mdsMatrix                                     [][]ec.Scalar
}

// Executes the Poseidon hash function
func (ctx *context) permute(p Permutation) {
	switch p {
	case ThreeW:
		for r := 0; r < ctx.fullRounds; r++ {
			ctx.ark(r)
			ctx.sbox()
			ctx.mds()
		}
		ctx.ark(ctx.fullRounds)
	case Three:
		fallthrough
	case FiveW:
		for r := 0; r < ctx.fullRounds; r++ {
			ctx.sbox()
			ctx.mds()
			ctx.ark(r)
		}
	}
}

func (ctx *context) ark(round int) {
	for i := 0; i < ctx.spongeWidth; i++ {
		ctx.state[i] = ctx.state[i].Add(ctx.roundKeys[round][i])
	}
}

func (ctx *context) sbox() {
	for i := 0; i < ctx.spongeWidth; i++ {
		ctx.state[i] = ctx.sBox.Exp(ctx.state[i])
	}
}

func (ctx *context) mds() {
	state2 := make([]ec.Scalar, len(ctx.state))
	for i := range ctx.state {
		state2[i] = fp.Zero()
	}
	for row := 0; row < ctx.spongeWidth; row++ {
		for col := 0; col < ctx.spongeWidth; col++ {
			t := ctx.state[col].Multiply(ctx.mdsMatrix[row][col])
			state2[row] = state2[row].Add(t)
		}
	}
	copy(ctx.state, state2)
}

func initPoseidonContexts() {
	contexts = []*context{
		// threeW
		{
			spongeWidth: 3,
			spongeRate:  2,
			fullRounds:  63,
			sBox:        quint,
			pType:       ThreeW,
			roundKeys: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0xcc92a4820ccb5378, 0x37b76efe5169a9b0, 0xd691dc62fea5f8ae, 0x02f9dadabbc991f8}),
					decodeFieldElement(fp, [4]uint64{0xb0b78665580b88e5, 0xa9737a3629f1d0da, 0x3c43953d9584b229, 0x1783bec6c3570a73}),
					decodeFieldElement(fp, [4]uint64{0x377ead8957340c7b, 0xa8ecfe80106e3f56, 0x6cf02af0390756bb, 0x28c01df6666b0419}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x00f95df0a63992b4, 0x928b7c0954bbf25f, 0x9c7358494bd7fa35, 0x0cd102badb124ebe}),
					decodeFieldElement(fp, [4]uint64{0x4741757bfd7a51d5, 0x9bd16733e18d5f62, 0x0a40dacf31757cc3, 0x020f1731eef7b419}),
					decodeFieldElement(fp, [4]uint64{0xdb98fde08cdbdf52, 0xdd370e0aeaa49d68, 0xd2fdadf84d097d0b, 0x1e3339ede4ca0304}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x3fdeb28371bdad60, 0x0d88d592e2ed2aa0, 0x3a82d8f7ed72345b, 0x0d6f067838fca70a}),
					decodeFieldElement(fp, [4]uint64{0x5678f03b729c756f, 0xaae2a9a7e8a75d4b, 0xba391b81704ee5a7, 0x3fb917be23bf82c2}),
					decodeFieldElement(fp, [4]uint64{0x57a0d21951ec6995, 0xd1015a3bed8b2cf6, 0x0001fe8aa2165058, 0x33c766ac8e43ad4f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x290a2fe9afa8b58d, 0x7c989b533d123fe0, 0x94d630d4ae7abe1b, 0x1e6870fd342783ff}),
					decodeFieldElement(fp, [4]uint64{0x7a61118c8634e0da, 0x2ce00c71e0269484, 0xa8ebe61e079a2b96, 0x31841af166bee119}),
					decodeFieldElement(fp, [4]uint64{0x488e655616f6d5af, 0x33b3806b1b222d1f, 0xbd3802dde999d1fb, 0x1ce218cbe1cd33d3}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x76a8f536b6c1d1aa, 0x5d9d66103377c001, 0x2e07478d2cc23cdd, 0x333772c14246fd78}),
					decodeFieldElement(fp, [4]uint64{0x7e85bcf2bc461920, 0x7758630e9376e920, 0x352c070ac03c82e9, 0x0425e6a47af44e68}),
					decodeFieldElement(fp, [4]uint64{0xb75fb677a32b6eb6, 0x32f0ed60c76f3d8f, 0x9604a5f04595308a, 0x38433342a831c71d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x3e87306310543211, 0xde66ef0b0d314f95, 0xf2565881f0eefbde, 0x04c793fc2c4db319}),
					decodeFieldElement(fp, [4]uint64{0xd979128f18ad105e, 0x44ceb9b825ef2f8a, 0x1a447f187729b2f1, 0x2a5c181209489bf9}),
					decodeFieldElement(fp, [4]uint64{0x5f155ae760f26f41, 0x7fe5640fbec1b3cf, 0x489dbf28f6a7526a, 0x36e4781a629fcfe8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xfbc09705713e5547, 0x0fb349e2a5db5f62, 0x8c643fd1f022ce15, 0x2348bed14360723e}),
					decodeFieldElement(fp, [4]uint64{0xf4aea30516d13d5a, 0x8a137aa16ac4e190, 0x688ee6b43d5ed625, 0x11b371d0f4a9d4dc}),
					decodeFieldElement(fp, [4]uint64{0x1bd2657121fb8ebb, 0x327e9734bdcdca9a, 0x548877975b2de198, 0x298d37b85dec2b7d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0717492056421f43, 0x67c772ad7537dbd6, 0x754ad6a519b214ce, 0x2ae8b1483af5eb5c}),
					decodeFieldElement(fp, [4]uint64{0xa0c488d850d653bf, 0xc4e4ddaa8f585310, 0xa5830b0a6f119cf3, 0x1e3050261e80372f}),
					decodeFieldElement(fp, [4]uint64{0x18ca349999de7c5d, 0xd9159cbdbe2a26e6, 0x21201b6f28daacb1, 0x1f28f3d4242e8dfe}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xfb688d816dd50234, 0x55681fcacd87bd25, 0x3d9e9164c94aeda3, 0x1d469a8eeeb67577}),
					decodeFieldElement(fp, [4]uint64{0xf72a04d51fae0ead, 0xc911877303f084f0, 0xc3d94b9f840c68f5, 0x38d6ecd101eb008b}),
					decodeFieldElement(fp, [4]uint64{0xcdbcb92e172657cd, 0xd074df4bf8bb8b11, 0x11e9658aeb909873, 0x3b65f8d1d63bd4c2}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc09a5c7361c89109, 0x466aaee1cad433d7, 0xa7c83b6c8aaa9e65, 0x34cf76f034657b1f}),
					decodeFieldElement(fp, [4]uint64{0x9dddc6fc2e19c1e8, 0x2404cc7e007a7385, 0x0226d2d6c126a481, 0x2542cd1460d86940}),
					decodeFieldElement(fp, [4]uint64{0xaed5b862358205ed, 0xe05fa6e600bbfb6d, 0x9268bcf3813f4f4b, 0x28c7560c1ec84217}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xea6ff6b84152583f, 0x6d7eb08f0994a537, 0xf70cb9f8f4ce44ba, 0x255b3e6138146a37}),
					decodeFieldElement(fp, [4]uint64{0x58ba7690ac57cc28, 0x171665e32d323f6a, 0xae32417f5cc272f2, 0x34b63eb174ec334d}),
					decodeFieldElement(fp, [4]uint64{0x3c33ea087d1e1fbb, 0xc0139fffe734fa07, 0x7f05ecd61f1aeaea, 0x35e0c2b608547ab6}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xe05d843a2f0347e6, 0x3830d9e1edded022, 0x031a30d9bc4b1ff9, 0x38115c9f35b03dcc}),
					decodeFieldElement(fp, [4]uint64{0x3a22580a05685b5c, 0x3b5ece83e7913403, 0x3003b3e59a455f35, 0x03494b3eea9bd553}),
					decodeFieldElement(fp, [4]uint64{0x3349eb03c721b76e, 0xf3d557a817785c51, 0x3c064a816955cfcb, 0x293d819ac238e233}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8b63c45e6c1ec9ca, 0x8dae11940b055771, 0x475b951f5ba2bb33, 0x29bcabb23f2d09b8}),
					decodeFieldElement(fp, [4]uint64{0xeea2ee0429453090, 0x7130f83c2b57e3f1, 0xe4c4e9a5be98e202, 0x00652648b3548800}),
					decodeFieldElement(fp, [4]uint64{0x8b6e7933e7539118, 0xd3d6736785276926, 0xd91d77661f9e0c73, 0x12877b538224e235}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x9716b2a996da3d6c, 0x4ec11dd787457ffe, 0xa7a11c041ef5847f, 0x093c115bb0f28811}),
					decodeFieldElement(fp, [4]uint64{0xfcd2deef68731829, 0x60341ed7fe8faab2, 0x4cce60f7d5407101, 0x2434aedf500ce531}),
					decodeFieldElement(fp, [4]uint64{0x0c14ca47897a905f, 0x2a8aae13dc9b6fd5, 0xeb1b566e4e22a28b, 0x1291b3e81b69a2d7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x81ee4e14d1424499, 0xd57e7dee499ac3e8, 0xe633f6969ea07641, 0x222013376f6283e3}),
					decodeFieldElement(fp, [4]uint64{0x0bdc2d6755f4d889, 0x83a4c00d89cc10d8, 0x55d073e0328ae1d4, 0x09067a146776a120}),
					decodeFieldElement(fp, [4]uint64{0x8d39f12d9cfa27ab, 0xb3d718a0283920ce, 0x0ff1679bb0538c75, 0x3a40dc2198f80b69}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x2b154be87b00b934, 0xacfb53d408183874, 0xd7bc42845f08f63b, 0x1576532889a8dd5d}),
					decodeFieldElement(fp, [4]uint64{0xe4668528931de9ec, 0x133b53d095eaf820, 0x06ed2e6770520bfc, 0x3db4ef72bd8bd585}),
					decodeFieldElement(fp, [4]uint64{0xebdd2b72247ad9ba, 0x92c706d702670019, 0x8a98051141607f16, 0x2d1e1687b8b93e39}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4f3d9fbc48d5bdaa, 0xa5ab57587c1092bd, 0x06a49e8f64296b16, 0x323e9676d56bd579}),
					decodeFieldElement(fp, [4]uint64{0x3d7e682ed25758af, 0xd3a1eac53dce5947, 0x89bfc6f736af1478, 0x1b8309450bc45003}),
					decodeFieldElement(fp, [4]uint64{0xe9895791b9055bb7, 0x6ffdaa786b7add69, 0x39e5314babba6ab0, 0x3beb7f00630155ff}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8f01cd70440f3cad, 0x74ad3e4b5acf78bf, 0xfdacedf9fc56a9db, 0x1fe58500a9141b81}),
					decodeFieldElement(fp, [4]uint64{0xab54eddc3675b968, 0xd67ccc4453494595, 0xac504e2c1fd1b1d5, 0x32aad1dc3e6fe3bc}),
					decodeFieldElement(fp, [4]uint64{0x867c0e50ca1721cd, 0xd504c78044c18c0f, 0x4ea45f406877315e, 0x07a380f595acad20}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x47bffb9766ba8589, 0x0948b5a7b2ba9fc7, 0x154114747411f2ef, 0x09fa52f7acb1009c}),
					decodeFieldElement(fp, [4]uint64{0x1f6efd68869c376b, 0xfdae2c68c47710a4, 0x514ec41c9f2196f5, 0x2835d3ee4caa0b46}),
					decodeFieldElement(fp, [4]uint64{0x46b5a226ca29b93a, 0x694767919087a59d, 0x8efe475c9ccbdc09, 0x14e2d97c0abb872d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb26af75f1333e086, 0x743f2a8288a18b30, 0x06820ff86dc1280d, 0x0722e1113d90324e}),
					decodeFieldElement(fp, [4]uint64{0x3f54d8dce2ba8396, 0x20c7c7fc6a66fdbd, 0x2c43cde8d53df0bc, 0x20b78ceb6e0df029}),
					decodeFieldElement(fp, [4]uint64{0x53bc972b8cd0ee31, 0xfc5174ead595f352, 0x3fd84d46b44bc82f, 0x32e168964ba20a86}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xaf89494f891ba4d3, 0x8311739321d846f7, 0xf871e90b768909d8, 0x2e61cd35d9d990f9}),
					decodeFieldElement(fp, [4]uint64{0x604cc4d4539f8b5c, 0x8543bf95101c0144, 0x74fb0700ec139891, 0x2ded160893ae32d0}),
					decodeFieldElement(fp, [4]uint64{0xee9c2b42a9f309e5, 0xe9d8e0a8fbbf7081, 0x2c35882854222749, 0x16577ae073be8223}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x5dab4f895af005d3, 0xd8c34711913feebd, 0x57e20ff2e0177574, 0x187e88ba7cccdf40}),
					decodeFieldElement(fp, [4]uint64{0xa3b2cb5f2091a846, 0x00b7d8159e5f7b00, 0x605f57c10f8d34b8, 0x0a60ab41c11f95fa}),
					decodeFieldElement(fp, [4]uint64{0x4cfc2bacab72b617, 0x9808a9e9a4d41e10, 0xb210b493ce3991ac, 0x2914e18873f7378e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8a68ebf9b71d74e1, 0xc13006cc008534ab, 0x0e95409a41738505, 0x06c6f01aa8ca190a}),
					decodeFieldElement(fp, [4]uint64{0x8d0b62d67bc609af, 0x580c3d3c56308506, 0x2c06b82f190cc97e, 0x28ef788c2018eae1}),
					decodeFieldElement(fp, [4]uint64{0x61ffd058201c6af6, 0x4d3acc761685f5b2, 0x6118fa56b56e41df, 0x26d45b1aa0e97288}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x345d26b767d678ba, 0xdf329f2937cd1548, 0x6930d71722c6d1d7, 0x39ec87e4a95dd94e}),
					decodeFieldElement(fp, [4]uint64{0x7947653a910fb6ed, 0x0febc1b302e807ae, 0x3376f4005d194dfd, 0x10bff0fcc663269e}),
					decodeFieldElement(fp, [4]uint64{0x3b178fadeff93bd9, 0x7a192c23aa13f113, 0x9f633d2c88a7acdb, 0x2c58d0a4646e33ac}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4af777ac6f1b25b4, 0x83fcb1f0760a5a35, 0x387bbcaf2b69a029, 0x255a12f7505a81b7}),
					decodeFieldElement(fp, [4]uint64{0xd40ea129aa9bfc8d, 0xfa0e2ec9e3c60904, 0x9c12e1849ea83292, 0x1ede0f41c98e5a78}),
					decodeFieldElement(fp, [4]uint64{0xf270bc20b0513bab, 0x9da753ea227e2ffb, 0x159e3f531df61429, 0x37d6ddb158b07eee}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x841c1167c2b8e6d4, 0xea126addb90ed9ca, 0xb8dbeac43e039ba1, 0x28f7cfe6a0b76b75}),
					decodeFieldElement(fp, [4]uint64{0xaeeb8652f0cb20c5, 0x354276387e530b05, 0x619f089e041d0628, 0x32e1ed2dbf09026b}),
					decodeFieldElement(fp, [4]uint64{0x85ee915a0eff5dd9, 0x6c891f2d66e635b9, 0x11eb66c02c2aee88, 0x3db54eb1d8c52861}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc4c2a1354e92b2e2, 0x1620ce561025d033, 0x1458eacd3593f187, 0x025c178b222bb325}),
					decodeFieldElement(fp, [4]uint64{0x4ef357c2d459db54, 0x053cbeb6be85d1c6, 0x985fa72c1d2d2fbf, 0x2611a94466f9ef6e}),
					decodeFieldElement(fp, [4]uint64{0xd025c25ec92be980, 0xe2af51fadb592ea7, 0x78e8e1e5c7c819fe, 0x2454b42934012ff7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1e7fb4674783d633, 0x1306844488f15727, 0x369760f1ae2aecda, 0x3f40092e86c6ff92}),
					decodeFieldElement(fp, [4]uint64{0x24d4113cb6e6fe9f, 0xf7c1f39cc762c146, 0x31089bf39dfb32d5, 0x1660a3b2599d67d0}),
					decodeFieldElement(fp, [4]uint64{0x437a32185ba5e9d2, 0x49dfb7544174935a, 0xa9f194c64d1bffba, 0x0530f1045ffb5c20}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xcb9cce48e9c27324, 0x980122bbb57b427d, 0x8f63f25bf8132b99, 0x24be84fe06b6e3df}),
					decodeFieldElement(fp, [4]uint64{0xec5a196360fa6d88, 0xcbf689e363bfcd74, 0xe3ff5ea1e856c643, 0x05172209042ea906}),
					decodeFieldElement(fp, [4]uint64{0x1366d31623d1c611, 0x4a01c3dcdcdf95eb, 0xcb65ac8ff460cc9a, 0x3cd4ad01b5ceccb9}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa729f3519eaac4c7, 0xe9755aab50c69b43, 0x7baf594795cf642e, 0x14e9c2ef46ae0699}),
					decodeFieldElement(fp, [4]uint64{0x976ba10ebcceb3f9, 0x95a71f59794633f5, 0xba79ab97f811adf1, 0x33ca75b3f0eee249}),
					decodeFieldElement(fp, [4]uint64{0x66f4bdf1c401977a, 0x01ca703e109dc576, 0xab5ab4a3e7abe29f, 0x10e52756ef1e9062}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0a2d65b275c522f8, 0xa66794ecac42c468, 0x84fbe0a3e64b252c, 0x152dc28205bb989f}),
					decodeFieldElement(fp, [4]uint64{0xf256cebf8eb6a467, 0xa9be74e888b098c3, 0xa187049b82679c92, 0x28ee5dddc9ef49ec}),
					decodeFieldElement(fp, [4]uint64{0x26d13b8be1f48264, 0xffd9bf007efd4b57, 0xa03d0b7f462b723c, 0x371a00f9d51e93a5}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1085b1b564c36a89, 0xbcda222163972fc2, 0x03cb784e41a6afed, 0x2eb7e75c62ba1d7f}),
					decodeFieldElement(fp, [4]uint64{0xbdd23430aa4b6176, 0x835d73a49f9256f6, 0x516cad9b7b6bef5d, 0x2a779ccb539ab7a8}),
					decodeFieldElement(fp, [4]uint64{0x0f62a7fa9781637c, 0x3490dea36dc225b9, 0x4df829ffa55bff4e, 0x351ca417a677264f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x58ddc3c5093c81ae, 0xb84f7b41d9242e9e, 0xb94efe97b1c8afc0, 0x109ad285b5b20bde}),
					decodeFieldElement(fp, [4]uint64{0xe11714c3c3c31d16, 0x5b69affe456cf7ce, 0xb2b8a2bc9c3c6c49, 0x082af6fd0d473630}),
					decodeFieldElement(fp, [4]uint64{0x8cb2025d611f8af8, 0x9928db3aefa4e4a4, 0x253994a27c72a0b2, 0x1461c7f090cbda8b}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xe6331bbed92cd0f1, 0xee3589add766f22b, 0xfb5c3ac05146da01, 0x0b2ee969275d2a3a}),
					decodeFieldElement(fp, [4]uint64{0xf75a05502903007a, 0xb2fe0bbb2801d148, 0xecd7e52e3fc0ea81, 0x1d11a5a41cfdc731}),
					decodeFieldElement(fp, [4]uint64{0xd988d2920d39261e, 0xfd9b411fd260f42a, 0x28f6e0aaa224955a, 0x21936b3709c9ddd2}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xba45254f1508ed92, 0xcf6f96e8ecc28b4d, 0x17f6db99664de360, 0x062320c5546cfe62}),
					decodeFieldElement(fp, [4]uint64{0x216b2fa0fe0e667d, 0x9e03c630bf11a159, 0xbb3ddfaab9107d2c, 0x0de133d07af9bdfd}),
					decodeFieldElement(fp, [4]uint64{0x1c79dc65359ccbe1, 0x5d01bc3602563719, 0x07317eadd26c6398, 0x35617094e3c1ecdb}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x7478d0610442a97e, 0x6d93f63448d5a556, 0x1845f35474d65b80, 0x39042151c20fa218}),
					decodeFieldElement(fp, [4]uint64{0x0a8d5481db79d680, 0xbd59aeed451f7d73, 0xd0bcebb78ecf6769, 0x2f88df0574fd97b6}),
					decodeFieldElement(fp, [4]uint64{0xedc91cb72fe48a9f, 0xfc4ac8ec977ec807, 0x8bd33087cd536326, 0x25fe91a88205b569}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x031a71e5e49ee881, 0xa8d6a16e75745787, 0x18ce3b216324aff9, 0x1b1775ad9c2ba1f1}),
					decodeFieldElement(fp, [4]uint64{0xc7b9569d870d1306, 0x8e7a9ab2b6b562fe, 0xf06da068e58121e4, 0x1ca5356d21e15245}),
					decodeFieldElement(fp, [4]uint64{0xbaae1c2bbdee1249, 0x7c1c2c18212b5daf, 0xf02f13d8fe5a54b4, 0x06af4c91a11c52a5}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x18c33ec0db836a4a, 0x9f261fc54806d677, 0x6bc83d32da898d37, 0x0941789280992dab}),
					decodeFieldElement(fp, [4]uint64{0xa5033c878141211b, 0x15e9807041cbdbab, 0x0e56d62adf81e3fb, 0x096d4deca9fd8093}),
					decodeFieldElement(fp, [4]uint64{0xa2e8f6f45f3a1630, 0xc14ad81e10a8c8bd, 0x6699742642a6c6a2, 0x35367b942f71e94c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x5d74aee8a2192182, 0xd48756373e93c5bc, 0x1d638bc5f2d10cae, 0x20337671bc9d8145}),
					decodeFieldElement(fp, [4]uint64{0xf23cfa21a60a6b33, 0x1b54282c4c6ab45f, 0x29159cbdaacb193c, 0x3eb77d9c0afbd28c}),
					decodeFieldElement(fp, [4]uint64{0x5c8f8d2350441652, 0x6cede885c92b0f04, 0x623f0e8ffad7eba2, 0x3f7a9145cafc9f7e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1bba6187ff9b6cb7, 0xdc8737800c3f9ff0, 0x845870cf4d779d60, 0x0a0b04b04775f033}),
					decodeFieldElement(fp, [4]uint64{0xec347a8cbfa3f623, 0x56002bbe460926db, 0xb9e629fa432d3f24, 0x059830cd83d371e5}),
					decodeFieldElement(fp, [4]uint64{0xf0974e6620674486, 0xc2914a44af5b27dc, 0xaa600fb388961d6e, 0x1c7d70a41850b060}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x09c3e6844ec64c40, 0x804974280f792a3b, 0xfff42f87a37e1f7e, 0x2fbdb6819b90002c}),
					decodeFieldElement(fp, [4]uint64{0xf86b58c36df28ec8, 0x4ae57aa251bf34fa, 0x5f43a8edc44b1611, 0x1d419da8b49bd73f}),
					decodeFieldElement(fp, [4]uint64{0x97a92612ab015105, 0x22b6ce02ff0f4a78, 0x54f8b6ec6cac929d, 0x2fcd8a73ef6217c7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xac44ca6c34b07ca1, 0xc0a410ca09810533, 0x3bf75c9a37f2674a, 0x39a250eb25a92ea2}),
					decodeFieldElement(fp, [4]uint64{0xb43ef85ee9c1d925, 0x8b4c7dab24a2c546, 0x18dbc87cccd092a9, 0x285855ef5de96228}),
					decodeFieldElement(fp, [4]uint64{0x69be770a8ddbaf90, 0x669b88ff52e8714b, 0xacd5a60002149109, 0x2ef973b323eb9f2d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4d51bbdcc1cbb88c, 0x0139c1a1195d0dad, 0xabcced87523d3cd9, 0x11920f37c58326cf}),
					decodeFieldElement(fp, [4]uint64{0xa1f747d6f21e1752, 0xc97b8ca505eaa4da, 0xb5b6046f0bb930df, 0x31057f191bda3f1e}),
					decodeFieldElement(fp, [4]uint64{0x9aad0fe50ea897f3, 0xc8a7fb88fa583f92, 0x2196797946e293e8, 0x25154f7ac76edfc8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x5a2573b5ff110577, 0x4c343adf14173d9b, 0x73dbce8eccd37558, 0x17ace9f6367ac292}),
					decodeFieldElement(fp, [4]uint64{0x8a6a584b25e488b8, 0x5822c2c4668b2774, 0x01c209f6d3aa19c2, 0x2efb03fdba217d26}),
					decodeFieldElement(fp, [4]uint64{0xd4df42944c639d09, 0xbc1d58d6ec3fc980, 0xd535a6c94e329ce6, 0x1bd0b43cf6ac7b6c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x245dd4998df2a72a, 0x6e6add297776036a, 0xe5d9da726c6effc1, 0x2bbadb54fd142142}),
					decodeFieldElement(fp, [4]uint64{0x6cdbe5db827c86b9, 0xc079aa5a6183056d, 0xb8adc027605f0480, 0x30159ecc49fe867e}),
					decodeFieldElement(fp, [4]uint64{0xc72e8a29d2f9cfc8, 0x2c0c559743e089bb, 0xa6ed02d41a30a456, 0x26e945e1ec402504}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa2202e4d5b258f4c, 0xe1c659644c5bd9ce, 0xc3b43e3baa677f8b, 0x060ac054a5db07d9}),
					decodeFieldElement(fp, [4]uint64{0x5dac884b545bd96d, 0x9aad21bfafd908b2, 0x5e94dc2f4506d1ce, 0x1e4ba404df70c4b2}),
					decodeFieldElement(fp, [4]uint64{0xeb236159efedf7c1, 0x97334592046b6442, 0x029c9936bf7adbe8, 0x3ee4d554f56f3712}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x2770d117d11afea4, 0x67cf64464b316b2a, 0xa0be8c63cbd7f5a3, 0x3f190b8ce44186a9}),
					decodeFieldElement(fp, [4]uint64{0x2d054a00fb999fc7, 0x86e032bdd7e4c7bd, 0xaebd36d25477daca, 0x2f27f767edf5209a}),
					decodeFieldElement(fp, [4]uint64{0x47e043b0a82649c1, 0x264e60af0e67193d, 0x417ac07b2c83d6a4, 0x3e340445d8f274a2}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x37513542d19dfd9b, 0x1e93df71aefbcfeb, 0x7aea71ef6ccfbf37, 0x373a9dfa29c8a12b}),
					decodeFieldElement(fp, [4]uint64{0x6c523f2185d060a3, 0x9c18591f6e1c3a5a, 0x56543c7be2b082e4, 0x2cf7fb4f8e343302}),
					decodeFieldElement(fp, [4]uint64{0xaeddd3f9e45b697e, 0xac15f7520f8b42b9, 0x8a340dff2cc6f50b, 0x1187d223845b0f88}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xdad35f16aaed68fb, 0xb79595ddbc15bb52, 0x242c6975ee13c2a9, 0x13b37fdc3daa817b}),
					decodeFieldElement(fp, [4]uint64{0x9b1e76c6b262a284, 0xa9123bfbb82c0032, 0xe662fe5f488e695f, 0x2b70dc6b83faaf01}),
					decodeFieldElement(fp, [4]uint64{0x70ffaf1638ddb55f, 0xda778031843cc160, 0x9a3a65ed581eeae8, 0x205b55ea84e99f47}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd83e36ac7429d5d4, 0xe140e9deb97ec1e5, 0xf139c4a6c4aa889f, 0x198c04b22df46de4}),
					decodeFieldElement(fp, [4]uint64{0x5bf32b48b20de75d, 0x8bdab8e64f9bc5ce, 0x91fcfe79ae56b4ea, 0x2e333c8d9b7786b8}),
					decodeFieldElement(fp, [4]uint64{0xfbb5cb320d71595e, 0xae5a8b037bf59110, 0x89bba90bf61540ed, 0x0a47e570b4ea6490}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8044dec1ac6c90d2, 0xde0b66a567872230, 0x04fa93fb09fac1e5, 0x1eb02ce09ed3c426}),
					decodeFieldElement(fp, [4]uint64{0x20f4ab5e9e3dec64, 0xa4c10a25d354fb02, 0x7e1729b822dcfaa9, 0x11c879e6cc200160}),
					decodeFieldElement(fp, [4]uint64{0x8955a3ebc328cfa1, 0x97a2aca5f0efea8e, 0x663eac16ba02923d, 0x04b806f5fc40f15e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x66554eb1c4910d0a, 0x6033737fd91cca53, 0xc21f7b779d05b6e7, 0x3c671c8185114e52}),
					decodeFieldElement(fp, [4]uint64{0x805ef9dcf20b49db, 0x1563814791b2afc1, 0xfd3281239d59ff1c, 0x33c5d496652b2dbd}),
					decodeFieldElement(fp, [4]uint64{0x8f3a035260a761ef, 0x3d2415c273cf9e07, 0x4ad01e1635877fec, 0x26f047d6b5d2b3e7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x7726c83257481154, 0x9ef5942f85db2eea, 0x6e2a8364786001e1, 0x17ae35d76c90b990}),
					decodeFieldElement(fp, [4]uint64{0x2f2fe37dad97bccb, 0x339f6dead74c81d0, 0xb52ab074344555c1, 0x2111fb41b79e1ed7}),
					decodeFieldElement(fp, [4]uint64{0x2e976628f98a53b3, 0xee7e2e5e438e80bb, 0x3d2e11d12f40981c, 0x354608988a63494d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x67ad5dab07b98a25, 0x0afc389443f7706e, 0xdcad2c1d9406af2d, 0x27c26d5998de1ed7}),
					decodeFieldElement(fp, [4]uint64{0x9e7ceb88b4a61a89, 0x13c29ec0a20d31d9, 0x7ab0d9d86fe9b2b3, 0x26e82b78ed77fa2c}),
					decodeFieldElement(fp, [4]uint64{0xa59e7810bc1af909, 0xdbfb316a685ef8a4, 0xd521e81f4c4c6e24, 0x3c9f896389f9168c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xe70aa1de721edbc2, 0xa9b7ca4605c626a4, 0x7ff3595b74c94a57, 0x00fddd234b11d1b7}),
					decodeFieldElement(fp, [4]uint64{0xa2df7b8f0e3b6c21, 0x4c749a37b337f5ff, 0x78dbd6c9d34827b7, 0x33f13cbaa0e9196a}),
					decodeFieldElement(fp, [4]uint64{0xcd7585fa7f8363d1, 0x292cf1c908b1bacd, 0xab9f49dc6978cd85, 0x32060e681369e9d8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6c4f459c5edc9748, 0xeedce909e0746219, 0xe304dcda3b1ab0d7, 0x39c41360d52142a4}),
					decodeFieldElement(fp, [4]uint64{0x87181b816cbff535, 0x657315bff86c2742, 0x9f9ef883157141fb, 0x2cb7647a82d0e70c}),
					decodeFieldElement(fp, [4]uint64{0x5b8d2a8372d1c9c4, 0x416d858f2b6ff9f8, 0x7211437240dad844, 0x10aad98fc92ae62c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x84eac74a646e8246, 0x9754caf22858816b, 0x34f557cf2af1ee80, 0x39e3eecf71a7ae29}),
					decodeFieldElement(fp, [4]uint64{0x6e0fec7c22a2d24f, 0x0283536cd0ac92c9, 0x85ddbab5e9af40c0, 0x3f92e6654a83ebe9}),
					decodeFieldElement(fp, [4]uint64{0xe7999b9a9d1f23c9, 0xb579cd3a36a9ef25, 0x72b85b9484942bc3, 0x1a4cef4f366fa807}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x394c695e9d252cab, 0x3bebf4e3ca4ed0ba, 0xae9e13cf71ee8f6a, 0x2fe1d605af674260}),
					decodeFieldElement(fp, [4]uint64{0x35a6697b803d5f2d, 0x192d392c23c81a69, 0x2e102444c8d28be2, 0x145f74e079088845}),
					decodeFieldElement(fp, [4]uint64{0xdef3a9f71d53415d, 0xb4f67cba2c49a945, 0x49882de53c92a295, 0x295d8c45443dbc0a}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x49abb0f89eb19e43, 0x5d33b14a68f93a91, 0x822e0518ad06efc4, 0x0f10617eb0f69195}),
					decodeFieldElement(fp, [4]uint64{0xdd45b753aa32cb3e, 0xf4d29eed69b3b49c, 0xfb6cbbd325b14db6, 0x2d6cf48b81919824}),
					decodeFieldElement(fp, [4]uint64{0x8b9a3bb8dd01cc6f, 0x52644573b45f0fb0, 0x9d496d6b60229bc8, 0x2c691a5519e9c0c8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc61728f79da7e697, 0x399c9ee2badb2e13, 0x1e4f1df0b87dc829, 0x3e50344adf9e7018}),
					decodeFieldElement(fp, [4]uint64{0xfdd438569e98d90f, 0xc2a42392121a1e6a, 0xffe9c42af21e6c8c, 0x16591f51a54464ee}),
					decodeFieldElement(fp, [4]uint64{0xca6c9cea8c8f107a, 0x8c0a1e5e4b81ef93, 0xc29c88486db3259d, 0x1947350278ed8b4a}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd5cd3ae48b2b19b9, 0x7944e8fb27f2f29c, 0x78ef80a16f38150c, 0x3d9e5c3252cc09dc}),
					decodeFieldElement(fp, [4]uint64{0x644992e8640af67d, 0x9d6ad6628ea7b4a8, 0x15757e5ac90bf472, 0x0039e7c187e0b64f}),
					decodeFieldElement(fp, [4]uint64{0x462743f0126efabe, 0xecaad7435eff270f, 0xff017f0726c86f42, 0x328144c12fffacab}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x02e08bcddf9e3395, 0x581d8b63aed8fe69, 0x17fac769b508156d, 0x289a1a58eb1dc107}),
					decodeFieldElement(fp, [4]uint64{0x343724cac8bf4ea9, 0x06a70b2553057ed6, 0x10feb295922ea730, 0x057bfbceaa7f9d51}),
					decodeFieldElement(fp, [4]uint64{0x8c56e6a17f1021e4, 0x1737b057aa34afb8, 0xe10352d5a6b540a6, 0x25188b12757e81d8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd8ae8664bc19517e, 0x5470e4cd4ca7a326, 0xd50a60244fbba4bc, 0x1a6a14f5b7a8fa4e}),
					decodeFieldElement(fp, [4]uint64{0xf13d6609528f0889, 0x873e8750d50f2813, 0x987fe995cf281e6d, 0x06ed5244e5e6e55c}),
					decodeFieldElement(fp, [4]uint64{0x31735e3183b892b5, 0x8f9454ee641ca253, 0x24e705f873618549, 0x3d405c061d987d6d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x77265fbc01facade, 0x95246ae07cce8c07, 0xf40f5a2945a311fc, 0x1cbe945e02625d9a}),
					decodeFieldElement(fp, [4]uint64{0x90c6538a916ea298, 0x3e608bc7d2411e91, 0x8f590e5a44b6667b, 0x010e279901e0b4a0}),
					decodeFieldElement(fp, [4]uint64{0x53841c264b1d8d5e, 0xdcf8f753c705a54b, 0x7aaef43f2ea98d3e, 0x1ec2e81eba84f452}),
				},
			},
			mdsMatrix: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0x873762e6ffb4a5ca, 0xbb21d64fa314a778, 0xdd561175959cad06, 0x0bc7bd43470f271e}),
					decodeFieldElement(fp, [4]uint64{0x79ea43b97f1bfffc, 0x9eca5e028831b940, 0x0b654a6b390cb28f, 0x21a33ba4ebd3dff4}),
					decodeFieldElement(fp, [4]uint64{0xdce8e4cd293208b1, 0x77a14f1263f1714c, 0x2ae0cc0eab26cc70, 0x3185adbdc9321052}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb1620758f5caf318, 0x4fb24c86983bb1b2, 0xac0442e35cde96aa, 0x164cd45138652570}),
					decodeFieldElement(fp, [4]uint64{0xb833abc204f5612b, 0xa08f57225c1ffd9d, 0xe9c0db6969b0cc16, 0x25de1627ec1a5754}),
					decodeFieldElement(fp, [4]uint64{0x67be04f351680a4f, 0x823241c68dd5eaeb, 0x45304689367c2e0c, 0x1f690f9372cca3a6}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x51336adead4ab5a7, 0x15917ee6c2d6ec84, 0x17615d7114a87bdd, 0x06c364440aa3b6cf}),
					decodeFieldElement(fp, [4]uint64{0x81fab3c8f2ec2261, 0x69927ff59ca0038c, 0xcf47520851e6d9e0, 0x250b797d72cab6bd}),
					decodeFieldElement(fp, [4]uint64{0x302dcc8b61eea7bf, 0x7129acef2f2589b1, 0xa6c4a826ba863937, 0x2557460f3563ba3a}),
				},
			},
			spongeIv: [][]ec.Scalar{
				// Testnet
				{
					decodeFieldElement(fp, [4]uint64{0x5007b962b8c85392, 0x7d17933d1ef7c665, 0x6a278907afa2a9fc, 0x3e323718b3fe2a3d}),
					decodeFieldElement(fp, [4]uint64{0xd1032c6a3de44e99, 0x64af7d48a0248c54, 0xcce5c50c92cb64b9, 0x370a1c8b483740a5}),
					decodeFieldElement(fp, [4]uint64{0xfd3d553346c10d36, 0xd7e18e31b32d839c, 0xffaefb489e714b51, 0x071c3303f02d911a}),
				},
				// Mainnet
				{
					decodeFieldElement(fp, [4]uint64{0x33d61dd9a9a49694, 0xfd6c78044738884b, 0xdbd13764c7b0a052, 0x37c222ad32094770}),
					decodeFieldElement(fp, [4]uint64{0xd9711055c69cd333, 0x88a029e44316ad76, 0xdb6728cff856f1f7, 0x10b8df535d1ade92}),
					decodeFieldElement(fp, [4]uint64{0xf56da9908a21e6e4, 0xb81e87dced63d7f1, 0xc01e378e013ad559, 0x00613894aac2c350}),
				},
			},
		},
		// fiveW
		{
			spongeWidth: 5,
			spongeRate:  4,
			fullRounds:  53,
			sBox:        sept,
			roundKeys: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0xa4faf0b2bb7eb484, 0xab81cea2b62744ea, 0xd0016253b7cda170, 0x1b0d80ec33099575}),
					decodeFieldElement(fp, [4]uint64{0x0bf30654d86dfe0d, 0x499f53103a1c9eac, 0x903181d1946c6406, 0x31b7a30b55067894}),
					decodeFieldElement(fp, [4]uint64{0x77be51b947443061, 0x900b5de4b0668a4d, 0x9d6fbb592d64f6f7, 0x3afb2d84e42bf2c1}),
					decodeFieldElement(fp, [4]uint64{0xd7a3bc20c419d1a2, 0x5f4d09ec0dccf850, 0xfd19355ea9af9d38, 0x1a4079bec944d0b7}),
					decodeFieldElement(fp, [4]uint64{0x0000cf3f99603dc7, 0x02e5ea2546526bbb, 0xa3b137b7476767f0, 0x01228b122564eb0a}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc3e1880fc03afb72, 0xb9d4939b36099ef9, 0xc49b80e624829495, 0x0144287145b1bb52}),
					decodeFieldElement(fp, [4]uint64{0x6f39810a6de0ddd6, 0x1113cff1f3013cbe, 0x2a0290cbfa63e57f, 0x21bd8a2dd176472f}),
					decodeFieldElement(fp, [4]uint64{0x1a9d3644d3c28a3c, 0xab8dbfded10467f1, 0xb5fdb59b48be4b1c, 0x3fb20ee7d10aa652}),
					decodeFieldElement(fp, [4]uint64{0x9b2ed3b90c16a5ec, 0x4385d0487ce630e7, 0xe277e950be253cf6, 0x2c4952fc140f5c62}),
					decodeFieldElement(fp, [4]uint64{0x9c773a6a8a3faaf6, 0x39053377d3488f0d, 0xd9475d6d616d1093, 0x2ffdef2c45f92fe7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x03418b6f1b217a94, 0x2183ad97f9216848, 0xd0e5cea0fbcc4fee, 0x2a4bfede924fd52e}),
					decodeFieldElement(fp, [4]uint64{0x640ce944e862b179, 0x1dc7292fdcd00ee0, 0x4c84d28e77c73a97, 0x18819a8c83e5caf1}),
					decodeFieldElement(fp, [4]uint64{0x953742aaf0bbb1ba, 0x91a43b0328e50211, 0x499adb0e47b9973a, 0x27491c11f31b02c0}),
					decodeFieldElement(fp, [4]uint64{0x95a0c34877f5d8e4, 0xa568711684a35698, 0xb4eec3e01c3495a4, 0x26f3803529462b5f}),
					decodeFieldElement(fp, [4]uint64{0xebdae5032bff19b2, 0xa88447a398a82f13, 0x00f341b04de6b6cc, 0x357d6b04aea8e2e7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6fac78dd5e630e7a, 0x9c146db799944c29, 0x126399fbdc1416c6, 0x374ff0ce4ff93b8a}),
					decodeFieldElement(fp, [4]uint64{0xdeb51b852e080118, 0x9f9e0c707af38b23, 0x06c43643a24c2f63, 0x0db668bba4187fed}),
					decodeFieldElement(fp, [4]uint64{0x14ce2b43fdeb323a, 0xd194307fa82283d8, 0x2eaf6c608c0cefc5, 0x0f95ad713ce55a8b}),
					decodeFieldElement(fp, [4]uint64{0x2c5a83999f86cb96, 0xfb4cc88c13ac01f9, 0xc7a19fb62eb440bd, 0x2c8aad1b2850617f}),
					decodeFieldElement(fp, [4]uint64{0x3c8942632cb86ee7, 0xc87ee22a2e300afb, 0xc2d5bd8eee30171a, 0x2f1d6ff7cb3fb8bc}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x73a0fe221c6c3621, 0xd0bfc14ddfdb0553, 0x8439cc76420f034d, 0x3dde452368433e25}),
					decodeFieldElement(fp, [4]uint64{0x3b183485d618b17f, 0x28b707d64bf9e9ee, 0xe6457d74c9fd6c47, 0x0e51d4062fe7f002}),
					decodeFieldElement(fp, [4]uint64{0x60dcf4087bf59f1c, 0xadf402e1385c0729, 0xe18b159d0164d3b8, 0x35a3c6609c13b857}),
					decodeFieldElement(fp, [4]uint64{0xbb3a9711822833e7, 0xac77171938468f67, 0xabdb6184d2c1795f, 0x1c2a82950d90f6cf}),
					decodeFieldElement(fp, [4]uint64{0x1dbc0b8ecca1d706, 0x389a26cda4721619, 0x051873324f0b79aa, 0x2d5aafa99b9dca10}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x42c2a2bdb036c28d, 0x4743d7c691e9734d, 0x26415397168e0b31, 0x366dbed899f9cf9c}),
					decodeFieldElement(fp, [4]uint64{0x795c2eb2c9cb73bd, 0x84b666cd3991d96a, 0xd07a4243610e4b3e, 0x2fef04890eddeb36}),
					decodeFieldElement(fp, [4]uint64{0x3888be10cc233d27, 0x58c5a81e759d0c03, 0x854bf803aa482550, 0x15cf3056cf773ac9}),
					decodeFieldElement(fp, [4]uint64{0xa8e04aa9f1a40dfa, 0x2791b299d2c76abf, 0xadfc16795ed4d5bc, 0x189270806d8593bb}),
					decodeFieldElement(fp, [4]uint64{0xf7ae4d47e3976ee6, 0x28400cb67d1fbc41, 0x4a5c8d69bfcc2e4d, 0x24ade7b373c67f20}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0ba0810d2f1c1921, 0x0cee13980323510d, 0x4ededd9144b28358, 0x0066037dafd70783}),
					decodeFieldElement(fp, [4]uint64{0xf8d40b92fd3f097f, 0x5e20e485ac888aa3, 0x71cfa1fbffa58343, 0x1b80475a09def258}),
					decodeFieldElement(fp, [4]uint64{0x197780f43b6ef417, 0x2103aafb4e883a6e, 0xa103554f2383974f, 0x1406bedff334da94}),
					decodeFieldElement(fp, [4]uint64{0x59faf5e2fc564538, 0x2d438198465273ca, 0x2e22b876804b4b73, 0x255453338451db95}),
					decodeFieldElement(fp, [4]uint64{0x21e7663eacec22eb, 0x52267fe54d8ed2ea, 0xe5f8a8f6927f4fa5, 0x042a6d6ff2f12b93}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xf306251feefc3c1e, 0x726c1ac4db435248, 0xa455fd8012e63e43, 0x18069a8a3b8d789f}),
					decodeFieldElement(fp, [4]uint64{0x6461b8e92cdfb945, 0x4ec8bb13c26707fc, 0x5a9a211673f1667c, 0x2c4479002ce7627f}),
					decodeFieldElement(fp, [4]uint64{0x9bceaa44db45e1ca, 0x96b8e6c1f25ee20d, 0x272f82fce7dcd07c, 0x0b0b976390fcd293}),
					decodeFieldElement(fp, [4]uint64{0x262aadd63fcd71b2, 0x1c686eca9d3f714d, 0x84e1e427af8f23f7, 0x1abb8bebd520c36e}),
					decodeFieldElement(fp, [4]uint64{0x4a937f7ef46ebc9a, 0x50d64340f0c95a5a, 0xa04d84001f13346d, 0x136ebe5b7afb8333}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x33cb699b56f69229, 0x2f57e7664e268c7f, 0xc0835177889dd490, 0x372e81a3db787aa5}),
					decodeFieldElement(fp, [4]uint64{0x94341c1f5585a3cf, 0x423c837c620358de, 0xb49e22df52a8dd4b, 0x0e4fb7489303d0ec}),
					decodeFieldElement(fp, [4]uint64{0x88f1cd7b1cd580df, 0x49d485e2e583319f, 0xfadca837221270da, 0x179e6014a1cd9102}),
					decodeFieldElement(fp, [4]uint64{0x2afdb2a5673edf14, 0x0009e3cc93cb1212, 0x45d0cae85b9afe01, 0x072ca709f811e470}),
					decodeFieldElement(fp, [4]uint64{0xf22c53f55f5eb757, 0x4dd23f2734c0aa43, 0x1414c8430db18d1b, 0x3517938ab55dc125}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xfab6b67f28198895, 0x34545d826591d158, 0x2020a1d496ba0662, 0x3cce1b1cb06881f2}),
					decodeFieldElement(fp, [4]uint64{0xc99e892960cdbff6, 0xa03a60a761a8631f, 0xac44666b5bd29d5b, 0x26eb9fa0e0f90536}),
					decodeFieldElement(fp, [4]uint64{0xeb7e87a9934d1616, 0xf8cfe55892bab928, 0xc58313a88e8bfaed, 0x28c3661bacc336af}),
					decodeFieldElement(fp, [4]uint64{0x27c26d019f91882c, 0x4fc8260580ec41ac, 0x8fe814e3616aa33b, 0x1dc56b8430ddeca4}),
					decodeFieldElement(fp, [4]uint64{0x863a5f09bee05f0b, 0x75f6cb7a2494503d, 0x50e5f73cb0908bf7, 0x19f0527bf9a8d051}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x14fb8267fcf55b07, 0x49d73cb74d68c013, 0x84e5b5b3234c58e3, 0x3c85f74a56a75550}),
					decodeFieldElement(fp, [4]uint64{0x4d0dec2e5151fbd8, 0x12c5d0c27b186658, 0x442b7f3393ced93e, 0x34653f070faaec4d}),
					decodeFieldElement(fp, [4]uint64{0xd40a353f89861e66, 0x62b06882507730b2, 0x0b8d19987f290294, 0x013df114a48086d9}),
					decodeFieldElement(fp, [4]uint64{0x4952e773181551a1, 0x77ceeca65dbe2af6, 0x4cd4b461428d8f89, 0x1b1100f297b7ee41}),
					decodeFieldElement(fp, [4]uint64{0x35bf57a209950b5d, 0x0c9b0947aec50eb2, 0x9fcadb07857ae67d, 0x0a94e088d119f56e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0344b4c182f14127, 0x8ba0b7aa84e6dd77, 0x10fdf6eda8ab64e0, 0x0c58f756bf85f14f}),
					decodeFieldElement(fp, [4]uint64{0x7ea685d135321cb0, 0x45381b5bf756063d, 0x5041198eef22f149, 0x279fdc489170aefb}),
					decodeFieldElement(fp, [4]uint64{0x000b79c7bdb65b92, 0x3971a5e7233ed117, 0x987eb1bd3c1ea02d, 0x224c1bea63f7e6e4}),
					decodeFieldElement(fp, [4]uint64{0x84984bc8560492b3, 0x12501cfa04e76763, 0x288ca8e7e08d1e4c, 0x091c79dfb6835f0e}),
					decodeFieldElement(fp, [4]uint64{0x60b2cf2e80ec20d0, 0x1e73a36c2bc74bf4, 0xe7879224d91bf598, 0x364e2a4ba36e3dc6}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x838c719e8a8a9917, 0x6f4131234dd1c6e0, 0x7de78d7c2af27cc5, 0x0a09ff35853a8f08}),
					decodeFieldElement(fp, [4]uint64{0xf8cd1c9ffb8d4d90, 0xdd9de4a600dfdaed, 0xffafd262f5e04dbb, 0x1d399fd65cb64808}),
					decodeFieldElement(fp, [4]uint64{0xa020c6b4b3358566, 0xce500cecc01fa996, 0xc87b17fba43ffc63, 0x2b0904fce52fc719}),
					decodeFieldElement(fp, [4]uint64{0xd31321fb7861530f, 0x35d894bdff612d12, 0xa4e327d5912a2e36, 0x0192d9055193063e}),
					decodeFieldElement(fp, [4]uint64{0x97e8d5c675799552, 0x2130bbb4386a1194, 0x20bea41bb88dd241, 0x1471994dd4c449ae}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4e19f614ad0226d3, 0x89390845d9294fd0, 0xa9684b6c00d2601b, 0x0d216ae90416975a}),
					decodeFieldElement(fp, [4]uint64{0xffe11da7f06afb3a, 0xdb2da138b349f1d3, 0x0c5ee5250c8beca1, 0x2ea1faae0f347ad5}),
					decodeFieldElement(fp, [4]uint64{0x209b9ab35792be75, 0xc1f4265c1f7e39b1, 0x3e1cfe1f15b69725, 0x0a08e86cca64be69}),
					decodeFieldElement(fp, [4]uint64{0xea37bcc2312ad4eb, 0x592a1f2b2b1f4a59, 0x3d6500952559a8a9, 0x0b5d1a8d9c317279}),
					decodeFieldElement(fp, [4]uint64{0x1dfd4f9d13a4b271, 0x0ae74ed0040d8545, 0x456ebea3a1257ad0, 0x0a645e75651df330}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc49c3b40352decfd, 0x20b47d2c9895bba5, 0x51063703e393a41b, 0x301cf335b56af4c0}),
					decodeFieldElement(fp, [4]uint64{0x48f255f4b612d119, 0xb9f355373db62259, 0xc5bacae96c9d392e, 0x22e0dd0b8897c75b}),
					decodeFieldElement(fp, [4]uint64{0x188774023c8ffa21, 0x86b30a01ec9d1a49, 0x69917042e3c0c160, 0x382681c094716f8b}),
					decodeFieldElement(fp, [4]uint64{0x21b16ee92009e8f2, 0x0540284019c36eaa, 0xb52452cfa338d448, 0x27024667d2aadf5a}),
					decodeFieldElement(fp, [4]uint64{0xd8445e4c52fee9a2, 0xa42126275b83babe, 0x4a83dbae9ee13e59, 0x209bb1772ee8617a}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x24a688aee0233190, 0x1d3af6853e78025d, 0x05af9cda59927080, 0x2c2afc74fe96fc6b}),
					decodeFieldElement(fp, [4]uint64{0xaea16e9f93feaee3, 0xe7de4b328d2c8ebf, 0xbc5770db6bff9e6c, 0x1bcc61bc098311c0}),
					decodeFieldElement(fp, [4]uint64{0xf484d2a731cf39a4, 0xf8cd9e719056730c, 0xbe0f6d3c720b135b, 0x2b7945331603a97b}),
					decodeFieldElement(fp, [4]uint64{0xa859c6df28e87060, 0x94d84e9ef24b08ea, 0xb789f93768b3444a, 0x2393d2dae491b0aa}),
					decodeFieldElement(fp, [4]uint64{0x7d2711d5122f1dd9, 0xd40ff8b5e56c2a19, 0x538d34b8657aebd8, 0x13bcb9327e9e086c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x777e77f52c5c4f4e, 0xdaf9c6774dc18964, 0x0f7da5862ccf3b4a, 0x29f1a63f498e36e3}),
					decodeFieldElement(fp, [4]uint64{0x2d32916af69173bf, 0xd010259ac45d5347, 0xa4738aa96e4a0b35, 0x3f8b2f531152c8e3}),
					decodeFieldElement(fp, [4]uint64{0x588632b8f1694885, 0x2416099cf31a44b2, 0xe59a8dd3801e713a, 0x16dd03c6d38f3d4b}),
					decodeFieldElement(fp, [4]uint64{0x319bbe9ade8dd052, 0x8cf30ea775439128, 0xe43c42cc90b7f26c, 0x12d6e69c22828f12}),
					decodeFieldElement(fp, [4]uint64{0xaa8c331196c83d5f, 0xd0ef4a49d07fb015, 0x13df043182e12d9c, 0x3952c5f9e0e80033}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xbd5ac6a98de3cbf4, 0x8296ff47777526d1, 0xf2065ad7a3855054, 0x344e785a02bfee70}),
					decodeFieldElement(fp, [4]uint64{0xdd48d366e64d5d3e, 0x4b0fd0c9886f060d, 0xe240ae167f355082, 0x110fd641a00a6f6c}),
					decodeFieldElement(fp, [4]uint64{0xf61f4476f6629a8c, 0x34c1d32f36f91d1b, 0x643a1cff102d648d, 0x0738d773a25e4792}),
					decodeFieldElement(fp, [4]uint64{0x8e12a036a5696b16, 0xa2d9a9aa374ebea2, 0xe625e71b33817d30, 0x04a6681e110dea0d}),
					decodeFieldElement(fp, [4]uint64{0x82e50f6fdfc02ea5, 0x686e8241f9617643, 0xa348ddfa28c2d97a, 0x14147d84469b33fe}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x71638abd12970322, 0x6ef1b53af83227d5, 0xc50e520bfd096916, 0x071fc84d786f2399}),
					decodeFieldElement(fp, [4]uint64{0x59b1ec07b476cad4, 0x1f4ca7151f558122, 0x2516139ff05e13fb, 0x369ec71f4f5d5421}),
					decodeFieldElement(fp, [4]uint64{0x83b5d32b7d89ec0e, 0x940acb9771e467b9, 0xb42293ba8e430585, 0x16a17834dc9400d6}),
					decodeFieldElement(fp, [4]uint64{0xbf5fbb5558f90810, 0x61688d5f65e1155e, 0x89db185498252cb2, 0x28a53cbff65cef5f}),
					decodeFieldElement(fp, [4]uint64{0xb71bcc92eb11fb36, 0x75a8309407e086fd, 0x95c13a5fb80b65c0, 0x0868c425d6897502}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb1c9e179d1a9d95b, 0xaa443f70aafbcd1d, 0xfb300f9f4c57a165, 0x2b3f4a6787fc5e01}),
					decodeFieldElement(fp, [4]uint64{0x84e9af05bd837520, 0x12aa3b94eec70209, 0xd23396aa60b47ff5, 0x370f69883edeeea5}),
					decodeFieldElement(fp, [4]uint64{0x1e4f78fc5c499389, 0xf61ffc5fd5dd12a4, 0x926c68482e925e1c, 0x2da728fb6c4a8ba4}),
					decodeFieldElement(fp, [4]uint64{0xcdaea69159a7a3ca, 0xe037c1b6268b0ecc, 0x926573846f067c5e, 0x19af09ade41da9a1}),
					decodeFieldElement(fp, [4]uint64{0x66ef3938f0f836fd, 0x807effce4e16e060, 0x070cceab15bb2b56, 0x2c688bdafd593602}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x796c91e79367ff29, 0x158ace2a2acb2859, 0x982ed2a00682f59e, 0x0da8ede2183b2c0a}),
					decodeFieldElement(fp, [4]uint64{0x5a9809c96121181e, 0xeb76fcfe3ee9cb5a, 0xa9910c5b3ec27fee, 0x2a26c9e2d7a5b812}),
					decodeFieldElement(fp, [4]uint64{0x4e0f69ffdd726c29, 0x1b9c08012f08af9c, 0xe71d0e4448ff0d57, 0x097b9e0d4ca5c72c}),
					decodeFieldElement(fp, [4]uint64{0x5b30d897a1bcad7f, 0x47fbfb02855d395e, 0xf66bd244548823e3, 0x08101b2fb6359a10}),
					decodeFieldElement(fp, [4]uint64{0x0d4d3d8d0219ba8f, 0x452cdf12614ddd73, 0x63cbe169cee5f50e, 0x1dabcbbbf066e753}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa8f322bd72a5b006, 0xe5608ba2985f410d, 0x3e7b908757ec0220, 0x1152f2cb18faaa02}),
					decodeFieldElement(fp, [4]uint64{0x4b8c3dab859a50c7, 0x621fd62cbed01ec3, 0xd86ffa837b34c8cf, 0x3d2302289eaeee5c}),
					decodeFieldElement(fp, [4]uint64{0x7d9e81fc30c8b4fb, 0x5b69464b69daf864, 0xd5202c5c9d08aa6c, 0x0654272c86ecc8a3}),
					decodeFieldElement(fp, [4]uint64{0xec9c77f7af6ee2e9, 0x09fdf5afef11b68c, 0x2997686283090d8e, 0x2613a55c545e9e4c}),
					decodeFieldElement(fp, [4]uint64{0x2b9188fd6ea78fdc, 0x0fae7ff78b28c6ab, 0xe8d575cec89c3d44, 0x354b4ffd5647fb8e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x69d2e847843b5da8, 0xf7630b2a16052f6d, 0x74491c3764cbc8fd, 0x2e5f385e5c252bc7}),
					decodeFieldElement(fp, [4]uint64{0x37ef391a07cbc358, 0x0fdedcb45ebcd235, 0x76693012657484d1, 0x32460729032ac3d7}),
					decodeFieldElement(fp, [4]uint64{0x88533a06765b84d0, 0xb28c30e05369f1fe, 0xcedf8c2305beefed, 0x374132d028a53792}),
					decodeFieldElement(fp, [4]uint64{0x0e959f9f8a21f402, 0x1a6b11a5a8ff0f22, 0xdb613671c9fa9a34, 0x3e5744ac03b51bef}),
					decodeFieldElement(fp, [4]uint64{0x088dd31980e57099, 0xe046eb6fbd58dca7, 0xc59ffb30fac1f7f0, 0x12f5a5f4ef00f847}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x94a2d57af55bf28c, 0xaa5c2a670c242c6c, 0x07ba749c2b090d86, 0x0af8e52802f065dd}),
					decodeFieldElement(fp, [4]uint64{0xd87e58273beca3c7, 0xbc5ef67ae95b55d4, 0x3e1d9565371161f2, 0x11c465b4b6e1031c}),
					decodeFieldElement(fp, [4]uint64{0xe4033086db6a54bc, 0x28cc0eaeac0dd7d2, 0xab2a0017490363e1, 0x2a420e4de39b1f9c}),
					decodeFieldElement(fp, [4]uint64{0xcccb353bca22e004, 0xc12cd853e1c8d1fb, 0x2e777e646951a678, 0x00365284ac37045c}),
					decodeFieldElement(fp, [4]uint64{0x18bcd0fb644b5cf0, 0x975871118638c4ed, 0x1fd4801a19ec1214, 0x1b13a9a77fdc2488}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x850175ea2cd208be, 0x8614d7500bdc8643, 0x66a8c8ab70868518, 0x0bff5f64df5f9f23}),
					decodeFieldElement(fp, [4]uint64{0x9d83f1a55cf8957c, 0x87048634f0dbe984, 0x04d317b1d2d12b97, 0x2bb9a30a72dbf6b3}),
					decodeFieldElement(fp, [4]uint64{0xd6dcfd461eebb8b3, 0xb9f2bdc644d64a0b, 0x7e82ec6ad814ad89, 0x0c6625bb284f733c}),
					decodeFieldElement(fp, [4]uint64{0xd9937ae27c9e27f0, 0x7e0ff48bf63457e5, 0x18d76b6c11d96aba, 0x3acf027a47f751f4}),
					decodeFieldElement(fp, [4]uint64{0x48f913d43485ace5, 0x19e62a880af1ff2e, 0xb4058ce470064231, 0x3f3fdefad6628246}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8c991bfba630b57a, 0x3110142428dd86d7, 0xcd8c1aebb233ca3b, 0x1c7f036b3fe99916}),
					decodeFieldElement(fp, [4]uint64{0x72fc1265636fbe51, 0xb0297625a2cda472, 0xe266afc796f247bd, 0x2cc3642ceb943c33}),
					decodeFieldElement(fp, [4]uint64{0x3f26ae1d547f26bd, 0xe4661d01fa1c6e4c, 0x1ebd2f616cf5035a, 0x3b5d212907a84d8e}),
					decodeFieldElement(fp, [4]uint64{0x1b0b140d8b9db4b4, 0x5cda852f36f6a431, 0x5f66951b6b574f6c, 0x3d8659d725000dd3}),
					decodeFieldElement(fp, [4]uint64{0xe41edc2480ec1e1f, 0x1176755d56b93b4f, 0xca4f717f0758654f, 0x286fb96beab59025}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x5b133e058cbb643d, 0x0c4332ab476a0f2e, 0x28fec4c31414afe2, 0x0be1c844d03cacd4}),
					decodeFieldElement(fp, [4]uint64{0xda03c692cefaa855, 0x19c8cad22793ecb0, 0x67e76c8acb451880, 0x2ebbfa0f9366b139}),
					decodeFieldElement(fp, [4]uint64{0x6ecee77802bd60f1, 0xe7bbcabddd61b96a, 0x481ad1da57132e00, 0x01aa32a478687e0f}),
					decodeFieldElement(fp, [4]uint64{0xc183285f7c06ad9c, 0x4b30af266faecbdd, 0xa6f189d7a51dbbc7, 0x0cff588d6f06532a}),
					decodeFieldElement(fp, [4]uint64{0x494aed0b25484490, 0xa9c5bfd403d929d9, 0x3e69e2a10f0706b7, 0x193461bbf817e2c3}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8edf38c9de0ee9ff, 0xdacc84b295006833, 0xe5c4212c4411ac0c, 0x3af2ff22b99f94e5}),
					decodeFieldElement(fp, [4]uint64{0xaf67d79e96841e68, 0x919a2f00ad63d99d, 0x79e7f31a53348942, 0x16438477a984d4d4}),
					decodeFieldElement(fp, [4]uint64{0x6b329566a157899d, 0x69641f9d00984024, 0x920c3edd747fb2a6, 0x1c2753e64ca89842}),
					decodeFieldElement(fp, [4]uint64{0xf79d3227b2ea8a81, 0x5d5aa22bb941ee9b, 0xc6c49b40bc8b646e, 0x12395d7a81345f31}),
					decodeFieldElement(fp, [4]uint64{0xbe01d85bae31c285, 0xd8f8253a4fbe22cf, 0x0a1a302ad3c80cae, 0x1bb5629cc2c3cef8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8542808565d31155, 0xe40e5f9a645c8c07, 0xc7ed3fe4288a9330, 0x35bb2fa03f3be934}),
					decodeFieldElement(fp, [4]uint64{0x88a8d0089caee28d, 0xab9214303ff7a4fc, 0x6571b014f4b80639, 0x07bd1a5b3f90c253}),
					decodeFieldElement(fp, [4]uint64{0xd8a01ac336689bf8, 0x50122bebb0ea0624, 0xe99da95e4bdc9f41, 0x0e6bc7fa7fd08f44}),
					decodeFieldElement(fp, [4]uint64{0xce2982b2613cb20f, 0x3e43bf25069115e7, 0x2da5ccb43eb053a7, 0x1b067195c4476dab}),
					decodeFieldElement(fp, [4]uint64{0xad4c25c79f59c211, 0xd182ab9f05c571d1, 0xe14602a3f1b98ece, 0x34714d388e5a4427}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xdeb1121612cafcae, 0xfd81f9c66d47032d, 0xd3e00500c26787e9, 0x3cb2fc04104e950e}),
					decodeFieldElement(fp, [4]uint64{0xe075378f53909b77, 0x6002a4add8b8b40c, 0xd2953ee59861ca4a, 0x25ba93145576417e}),
					decodeFieldElement(fp, [4]uint64{0x68ead9cac80d27fa, 0x6d7e7bbfacabd5c1, 0xa13c3bdad1f6dbea, 0x11a222328f95389e}),
					decodeFieldElement(fp, [4]uint64{0x49003257577ab0c5, 0xa79e03aa6f3ee1d9, 0x8e77aab47300c028, 0x22b2f89ed6ea08b9}),
					decodeFieldElement(fp, [4]uint64{0xd89cd030b0d5e0bb, 0x2c58edac4d6fcf68, 0xcbe11adf0f708c87, 0x32d33765043eb897}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x90bdaf7cecd277cc, 0xf43a46fb9d744da5, 0x5afe3d55aaf1900c, 0x0ae08ad5e83a1290}),
					decodeFieldElement(fp, [4]uint64{0x77a1ccd414046afa, 0x3af25dcea87e1081, 0x73bbe0aa52320b46, 0x1fc260fb0aa12010}),
					decodeFieldElement(fp, [4]uint64{0xacb80761c38137fe, 0x529f14d134891170, 0xe2686701fe1c65fa, 0x18a5d67ab5297ef4}),
					decodeFieldElement(fp, [4]uint64{0xfd6cde24f384ce06, 0x8ce80b6df12592c2, 0xda68939405a3607c, 0x3fbfdc944b37c047}),
					decodeFieldElement(fp, [4]uint64{0xe9ccc975982bc6fe, 0xba08bb4c7747b539, 0x493266441abfa3df, 0x02161697fc91453f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x498608310dc3a7b9, 0x273433d408878378, 0xc2ba1eb902d218a7, 0x0b202f9ded4fd0fc}),
					decodeFieldElement(fp, [4]uint64{0x39993f4ad27e4135, 0x66d98c66d9a215bb, 0x2df5321a53f08775, 0x2f892ad9dbc4e894}),
					decodeFieldElement(fp, [4]uint64{0xaeea5a64f59879da, 0x388dea2b88312e5f, 0xeb4a2fd310a40b85, 0x18111f0e3fb63a6d}),
					decodeFieldElement(fp, [4]uint64{0x95b79092ad356e70, 0xd8dc8b7c590c9f27, 0xb991a6173f11b334, 0x144eaff647fc1954}),
					decodeFieldElement(fp, [4]uint64{0x70fe95a73a6b0ac9, 0x4c13c364c3322cca, 0xe81b258ce27a2bb0, 0x193850b9b4ea85b3}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc0676c015dda7671, 0xc418cf8b9d454531, 0x88cac7e59f452508, 0x163d7d0e000a7ccc}),
					decodeFieldElement(fp, [4]uint64{0x379a17c674d8e8e1, 0x99fd7589c5de86dc, 0x9d876d96a7f28391, 0x19f33e617225ddc4}),
					decodeFieldElement(fp, [4]uint64{0xbc069c4cec52867e, 0x9408a54197fe9217, 0x1f94cd754cd8e59c, 0x377efe6be4b7a2f2}),
					decodeFieldElement(fp, [4]uint64{0xc7e6dece9e3ca2ee, 0x235d56076f288dc2, 0xb0cd6f22d2198dd3, 0x2a1aa30e38a14cd8}),
					decodeFieldElement(fp, [4]uint64{0x61214304fbc40559, 0xce6b3ab69f0358c5, 0x69fd63d4fa5deb8d, 0x0c76ce1d841aa48f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xf941ae1bb8a8c8aa, 0xee3eb1032e5b3ada, 0x9b6c24cb4dcc6f19, 0x30307c71c4649759}),
					decodeFieldElement(fp, [4]uint64{0xcdaf74f115925d90, 0x9b873697b5ab1342, 0xb2fe5789e4884ce7, 0x1f1b806ec64a2e8b}),
					decodeFieldElement(fp, [4]uint64{0x4b792463e838fa1e, 0xbb0d564356cddb8d, 0x4c3c33dd8ee52914, 0x117c267191c08c32}),
					decodeFieldElement(fp, [4]uint64{0xb60efef961f2591d, 0xdcf38e017892fe9f, 0x374b63fb7eb8d988, 0x061e97701905e3fd}),
					decodeFieldElement(fp, [4]uint64{0x37a9ad4e637f0ef5, 0xcf54db2ed4ebf6b1, 0xeb471a7ec1120238, 0x14015e12ce8bfee7}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x752cf37c75fa1ffe, 0x57e7b45d81834dca, 0x377d9f9698ab7c23, 0x1991855e1e6a110f}),
					decodeFieldElement(fp, [4]uint64{0x8c6443f356fbcae1, 0xa7be33ea14745ce8, 0xf625c535e22f91a7, 0x15869773b4711a39}),
					decodeFieldElement(fp, [4]uint64{0xc76574bd7bd19184, 0x71454d6fa807e5f9, 0x11dc7a077d683f9f, 0x3813022a56ea91d5}),
					decodeFieldElement(fp, [4]uint64{0x8261e60ba0ae4aef, 0x5a1f9faf6e1706df, 0xad5af8e12e9c99b8, 0x251b1456f3038e4a}),
					decodeFieldElement(fp, [4]uint64{0x9d01f2972ff303ef, 0xc320bc7cf6349784, 0xc80bc8a71ce089ed, 0x0855ce9554ae8f59}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xab4e5d9c7983482c, 0xd53504d9d812920c, 0x2e73ebde12e19464, 0x36ad61c52c83b1de}),
					decodeFieldElement(fp, [4]uint64{0xac0e901543fe534b, 0x3f428a0827f58fd9, 0x48319dcadd0a0209, 0x1aefbcfd71da6eda}),
					decodeFieldElement(fp, [4]uint64{0x5c96e27eb7ad6f28, 0xe6401dc0894b97f6, 0x3379db36f64dcace, 0x08c1cf85e02e1150}),
					decodeFieldElement(fp, [4]uint64{0xe1985c2d5b295706, 0x41ea5940588f1ae1, 0x168b03f40d44425a, 0x1686382e99113d0d}),
					decodeFieldElement(fp, [4]uint64{0x517baea7f4dd19ae, 0xd1a73615021445af, 0x8356a898f681417a, 0x1d4979d07dd0bd2e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x98f004df69c87fcf, 0xe60f0c4f35b8f6c0, 0x83a7904c128e3adf, 0x203e58d08ba74baa}),
					decodeFieldElement(fp, [4]uint64{0x8d126e66c553e310, 0xaea9d8705d7cafa9, 0xf823d26e3733e971, 0x2501e796c9232f71}),
					decodeFieldElement(fp, [4]uint64{0xf816401557d4bb56, 0x441837b761cf0132, 0xf38de6923613aebc, 0x1cc851562680b5dd}),
					decodeFieldElement(fp, [4]uint64{0xda5a93f5d37e3ba3, 0x41a9344cb49c7425, 0x2d5508f9bea972fb, 0x27136b6d916446e0}),
					decodeFieldElement(fp, [4]uint64{0x0ac1cb9c6b99fbc9, 0x8e65a59328c48db4, 0xa633ac885178d770, 0x00c1daac8d8066c1}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x2987914343b2f7cb, 0x5bcde0ae431b0f78, 0x68643efa874ba2fa, 0x2ed44740fcd227c9}),
					decodeFieldElement(fp, [4]uint64{0xa2d86d396454eb3f, 0xeb8c41390f82b4f9, 0x21825cc5e037842c, 0x0c97dafb3bc38117}),
					decodeFieldElement(fp, [4]uint64{0x4ef21bf61b64082f, 0xd406297c3b49a07b, 0x3a7afdba58167797, 0x334494b7f95971c1}),
					decodeFieldElement(fp, [4]uint64{0x36d7d6b107bfe6aa, 0x3b3d470e9615d705, 0xd19aef745b389ed9, 0x1e3185448952bdc1}),
					decodeFieldElement(fp, [4]uint64{0x143e296fed86df48, 0x219d705f5691ccd2, 0x5f68bde265d9b9c8, 0x2636fabc4407c8fe}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1a09c2eaa2fc9785, 0x4f7339b811e22e62, 0x850e326e2f89c72d, 0x1de083cbb6238e5f}),
					decodeFieldElement(fp, [4]uint64{0xae28b950ba4c9550, 0xbc72edfbc7fe263f, 0x62c38bc62aeae54a, 0x21e0e0ce84a457f5}),
					decodeFieldElement(fp, [4]uint64{0x3a9a8e350bb04559, 0x66ed1fd4236ca8c4, 0xc42a09e34f0b73db, 0x1df0a4c997dd57ea}),
					decodeFieldElement(fp, [4]uint64{0xcbce8f4f7f0f1b82, 0x0f6fb4db12583059, 0xb6e1696d44882a54, 0x0bdc41112d3609fb}),
					decodeFieldElement(fp, [4]uint64{0x6c44ff6ccaf9f047, 0x27c030bd9931f692, 0x275da14607db5fea, 0x3bb6deec69119fed}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xcd3d2a4d9bce3f84, 0xa1ef3f83b4618a2f, 0x083a3dd3540ae6b2, 0x1da721d9d79dcbeb}),
					decodeFieldElement(fp, [4]uint64{0x5bbcaa23b3857915, 0x25b18b6571773b28, 0x7897deb399c38d50, 0x18fc227b28c41539}),
					decodeFieldElement(fp, [4]uint64{0xc1b13e242475bbf0, 0x0f199d24bfae45bd, 0xab10b5ed45b4667b, 0x3edd3d52744d6c6e}),
					decodeFieldElement(fp, [4]uint64{0xb471d635a6f4d95d, 0x804bbc403075f17e, 0xb53ce1e5b9d3bdf7, 0x083b893cf6355ec8}),
					decodeFieldElement(fp, [4]uint64{0xa842adf49b9d73ea, 0x626a7b00b09d4850, 0xe31fae058fe0fe5e, 0x38d7a74a17c0e67e}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xcf96477eccc93b14, 0xc031e08735873bf8, 0x646b0523a5575fb5, 0x3545f131e2ea6202}),
					decodeFieldElement(fp, [4]uint64{0x06dedcdb9039eb19, 0xe0f9992484cf8e85, 0xca72403fc5e282c2, 0x2005dcb82f42f58e}),
					decodeFieldElement(fp, [4]uint64{0x01131d96a923db59, 0x2bf47287f2061d1e, 0x79cf21111bfb9ec1, 0x24c47ef697d25773}),
					decodeFieldElement(fp, [4]uint64{0x10ace751630426ed, 0x053593b680bd0fbc, 0xb28d952b98229a01, 0x3bb6a4ad8cc95fba}),
					decodeFieldElement(fp, [4]uint64{0xa1b8ca97f3ff1f0e, 0x3cb7fa68a680297a, 0xc025616b7592edfb, 0x20279fefc6bc3b79}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6b437559e5d65567, 0x781b2f763dd0bbd1, 0x48f171108b9e4f99, 0x3939fc1c0382361e}),
					decodeFieldElement(fp, [4]uint64{0x5110a2e111bbcac0, 0xee55e37751417a84, 0x6302aa513b9cee69, 0x1560c77f9f647886}),
					decodeFieldElement(fp, [4]uint64{0x270f6d3bf9305087, 0x6ab54ae62eaa31d5, 0x1af9f268d5ffca0e, 0x147b1119815b61a7}),
					decodeFieldElement(fp, [4]uint64{0xde49e987e85ad2a9, 0xdda76cdda7592928, 0x20864f2433843855, 0x0fea0996abbbe24c}),
					decodeFieldElement(fp, [4]uint64{0x50fe8466bc1bd2f4, 0xb4b1e5c85a11a457, 0x09e558801bb164b7, 0x3c37271adf761bf4}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x386822af7be10a70, 0x5cdf242e374b5b25, 0x62534d3c114c2cc2, 0x28d13aeb7afd18fb}),
					decodeFieldElement(fp, [4]uint64{0xb60d002fb6156a29, 0x8cf289eab586ed5e, 0x7d9115ba530211ce, 0x1baea797e53eb613}),
					decodeFieldElement(fp, [4]uint64{0xa3b738a79c306423, 0x3c241a284e90469a, 0xd533bebc0d2b1298, 0x13b6f4e98bb1efed}),
					decodeFieldElement(fp, [4]uint64{0x8e3c3ababe9c89b6, 0xe3d5c55d41786835, 0x645205d7ae4c7a18, 0x2cb79f292c3ceb10}),
					decodeFieldElement(fp, [4]uint64{0xb5f6da347e7b822e, 0xdf15e71ea50a46cb, 0xc1a6504105a7b05c, 0x155c31cb327d8994}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xf156f680e4afcefa, 0x4d0e75e825d12d64, 0x1d36ee966f9c344f, 0x1dd0cb3c33176320}),
					decodeFieldElement(fp, [4]uint64{0xea6735cf06184f0b, 0x3fd8720c01dd558c, 0xf5ab07318350cb75, 0x345468d01197571d}),
					decodeFieldElement(fp, [4]uint64{0xcca06136df33bf42, 0x163c1d313f394460, 0xa0cc17d9e2e5e18d, 0x185b6e1d513f2ec0}),
					decodeFieldElement(fp, [4]uint64{0x05bc50db06f90c5a, 0x41bd921692423d3f, 0xc7b741e32666e0b3, 0x2ec2957f9889bb9e}),
					decodeFieldElement(fp, [4]uint64{0xe008061a23427d8c, 0x2404215a31f57ed1, 0x1197df5b39303fc6, 0x31ae7ddbf074c762}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc26c6793a0dc0799, 0xfe475498ac34fd97, 0xf03fd32b0def1c9a, 0x02aee16543dbcfbc}),
					decodeFieldElement(fp, [4]uint64{0x0df0268f17c75770, 0x5accf9b705955e74, 0xbd2c95daa04cde2a, 0x1e29ad86c9522187}),
					decodeFieldElement(fp, [4]uint64{0x071a400d47db2321, 0xc241700e2b55551b, 0xd4f3d1a258287220, 0x3cd853d7e685e251}),
					decodeFieldElement(fp, [4]uint64{0x0f2917669e6e6b00, 0xd65ad2a1c6cccb23, 0xd9d79d01eb4895ad, 0x2dd133389f8b1c9b}),
					decodeFieldElement(fp, [4]uint64{0x00e90f399c4eebb1, 0xc3e381892a1b68cb, 0x33be21b4e37d9ee5, 0x08bf1165cd0b8afe}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xf3ef1796ff053564, 0x5a0938456a60f31e, 0xbfe3cbb31fa2306c, 0x03e2582dda976a15}),
					decodeFieldElement(fp, [4]uint64{0xcd78cd04854ceeed, 0xb237976c1ff85f88, 0xf551e1a1596c4432, 0x36962c1285dd36ea}),
					decodeFieldElement(fp, [4]uint64{0x26beaf413f0b52cb, 0xa5eb00fc53b081c6, 0x7b43fa75fac10222, 0x118cc604f443ae8d}),
					decodeFieldElement(fp, [4]uint64{0x70f405dc2a323794, 0xb5906bb9d31882fb, 0xd5289d426740207a, 0x3bcdaefc028eb8f7}),
					decodeFieldElement(fp, [4]uint64{0xcecb3a3beb13201b, 0xc6f7c7e75813b6bd, 0x3e7d9a378c38e522, 0x3080100d4065bab2}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa5e10d8e4b2ba19c, 0xc4cdf5aeb4e858e5, 0xe84b93dc1b6272cf, 0x34ec238f7fb2cecf}),
					decodeFieldElement(fp, [4]uint64{0x22ba1b703204ecbb, 0x24b27b86a696ca6a, 0x868c17d9510f579a, 0x1af2a42617c499d5}),
					decodeFieldElement(fp, [4]uint64{0x8b429244429b0737, 0x8dd5bb81fe33a4a6, 0x8b65bbd08a90c813, 0x3c90182f16157188}),
					decodeFieldElement(fp, [4]uint64{0xc095c6f7e0e97aa4, 0x07eade0f1e886b9d, 0x81d0f57dd7dc031d, 0x178c698444ba7e40}),
					decodeFieldElement(fp, [4]uint64{0x5ea17b09ff19a8c1, 0x1ed893e043f750f1, 0x5d119bef5de0feb7, 0x1a1489e3a8b783f6}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x29e45320fcf885ce, 0xc7305c2ec60ce4fe, 0x56e97c5bd7f0347e, 0x2c015d1368957e38}),
					decodeFieldElement(fp, [4]uint64{0x9089fda652ba1f81, 0x57d6322703512268, 0x2a5486a0271045e7, 0x181729b80d976fd5}),
					decodeFieldElement(fp, [4]uint64{0x347b72dc6128e3be, 0xb33a6c2a5c71ba9c, 0xd6b67f182ec5392d, 0x0db501d81d7c9137}),
					decodeFieldElement(fp, [4]uint64{0xf2b122531e860eb0, 0x83ecf26c32ae2f38, 0x086ed9fc58990b49, 0x14c1b826c540117c}),
					decodeFieldElement(fp, [4]uint64{0x0bc9093faf2c2aef, 0x0c77380af0ee5cab, 0x1a7bcaebf129b5c4, 0x159dc49186052be5}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb2777d0a99f7b6bc, 0x855c1ff1e5e3c2f2, 0x336f6499b6c5fd1d, 0x28504d8e4fec0a4a}),
					decodeFieldElement(fp, [4]uint64{0xfa2cd134176b358d, 0xa5bec22f18736388, 0xf0cdb111a1504603, 0x19c8a299fd8d1ecb}),
					decodeFieldElement(fp, [4]uint64{0xa1491caa7bc99779, 0xde853bf4238d450a, 0xecdff50f31c9f1e6, 0x0aefa328af46662a}),
					decodeFieldElement(fp, [4]uint64{0x7beb47781e679056, 0xd4f3030870191f86, 0xc2a5cc4b11456bd6, 0x1ffb0c924a3aad9d}),
					decodeFieldElement(fp, [4]uint64{0x432eed89d5752253, 0xeada76aa20ca6e6e, 0xacd2d8ce898f03fa, 0x1051f72a8d0aba33}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xfee092bb45729388, 0xf9b9bcfed72eb6e4, 0xaf175da8256ee3f8, 0x09533de10d2cf07c}),
					decodeFieldElement(fp, [4]uint64{0x1dc0fbeeac090d3f, 0x57459357eb92a238, 0x73a9414a20b28b21, 0x01de15115cc6e43c}),
					decodeFieldElement(fp, [4]uint64{0xf1d8ae9e9bb10643, 0xf9f9937acb59ff5e, 0x7b6687d5f08742da, 0x0e8383073e613ff8}),
					decodeFieldElement(fp, [4]uint64{0xd590a23556c89022, 0xcee80e56ab7ef259, 0xb4ff2e8bd68c7053, 0x36edfc9de88184dc}),
					decodeFieldElement(fp, [4]uint64{0xc06d95db2a0ba0c0, 0x046df2e2f5aebb1a, 0xdae4f234e51d669c, 0x19a6e7626cc38cbb}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xaf68cd34cf000f98, 0xba9c4da844c45dec, 0x4c89e6f6ba2a941e, 0x0068dd341142db43}),
					decodeFieldElement(fp, [4]uint64{0x487ad583df6218be, 0x4fb79a2cbbaffb6c, 0x89241771202c117a, 0x0933434ab362374a}),
					decodeFieldElement(fp, [4]uint64{0xc625fe2366851da2, 0x168cd16aa9b1cc9c, 0xee13187660b56b18, 0x0fb9d46bb02b4944}),
					decodeFieldElement(fp, [4]uint64{0xad269cf15db8d605, 0x1cf5fab58e309fa8, 0xf0473ad640ea546a, 0x16eb4c91597fc874}),
					decodeFieldElement(fp, [4]uint64{0x90467b7b0a218d90, 0xecdbb505dcd4f6a9, 0xc7d44729c5c9a96a, 0x202bc2f290f1c679}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x30c009c1d8dfbd21, 0xd4200b4f525c2c9e, 0xe4b6278d2b310a58, 0x3cc809847241bc93}),
					decodeFieldElement(fp, [4]uint64{0xfff5ad7039e359ad, 0xd72bf12575ea1b09, 0x68a2a572cb347bfd, 0x10458d3b25ca06ea}),
					decodeFieldElement(fp, [4]uint64{0x751d40675d21f6dd, 0xe2d488b19df9eb6e, 0x17cc3c0ae1dd0edb, 0x3dda5e8981ec4493}),
					decodeFieldElement(fp, [4]uint64{0x704e9abc0bc8d834, 0xe80adb1d43c2e614, 0xddabe007ef17e261, 0x0c10596e3d675f79}),
					decodeFieldElement(fp, [4]uint64{0xb49d8bbdb1e8fe4c, 0xfd75aef98ccdfbf8, 0xc3171f52bff44019, 0x029c8ff241f05a69}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd0848e1bb50ccc82, 0x005c9c7cde6ddb9d, 0x3fe9d8cbb2f6e057, 0x3adba832efb70c12}),
					decodeFieldElement(fp, [4]uint64{0x4b294e3b163e3c40, 0x044ff43753014f1b, 0x4d704bc13f9aa5d2, 0x240737177f14e1a9}),
					decodeFieldElement(fp, [4]uint64{0x4164b4821e116076, 0xa15345ad21522d21, 0xcedd254c29c79c4b, 0x180734b830fc5e2f}),
					decodeFieldElement(fp, [4]uint64{0xfcb08e901c0531ba, 0x928c59937dc17c25, 0x0af7d8de76b51661, 0x357a405ba00a74f0}),
					decodeFieldElement(fp, [4]uint64{0x45b829385fa4a616, 0xd0715c725de24766, 0x6bfdaf3dc147dc69, 0x0524501f3243e314}),
				},
			},
			mdsMatrix: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0x873762e6ffb4a5ca, 0xbb21d64fa314a778, 0xdd561175959cad06, 0x0bc7bd43470f271e}),
					decodeFieldElement(fp, [4]uint64{0x79ea43b97f1bfffc, 0x9eca5e028831b940, 0x0b654a6b390cb28f, 0x21a33ba4ebd3dff4}),
					decodeFieldElement(fp, [4]uint64{0xdce8e4cd293208b1, 0x77a14f1263f1714c, 0x2ae0cc0eab26cc70, 0x3185adbdc9321052}),
					decodeFieldElement(fp, [4]uint64{0x3c8df6bfb859189d, 0x91613b95800ec20e, 0xb257a24e566ee6bf, 0x281582073c56d6cd}),
					decodeFieldElement(fp, [4]uint64{0x88a59fa936e61334, 0x9bf34f7f4fd6649d, 0x265dbc65dc782e16, 0x1d982df8253ad550}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb1620758f5caf318, 0x4fb24c86983bb1b2, 0xac0442e35cde96aa, 0x164cd45138652570}),
					decodeFieldElement(fp, [4]uint64{0xb833abc204f5612b, 0xa08f57225c1ffd9d, 0xe9c0db6969b0cc16, 0x25de1627ec1a5754}),
					decodeFieldElement(fp, [4]uint64{0x67be04f351680a4f, 0x823241c68dd5eaeb, 0x45304689367c2e0c, 0x1f690f9372cca3a6}),
					decodeFieldElement(fp, [4]uint64{0xf0a7808ab07b2dae, 0x932f8900573ee43a, 0x45dad3615641fdd6, 0x10efcce7382e6918}),
					decodeFieldElement(fp, [4]uint64{0x09c5eaf7596a5dcb, 0x24380d30a899bbe5, 0x8f0f9958401d2726, 0x0b9195d635c0a093}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x51336adead4ab5a7, 0x15917ee6c2d6ec84, 0x17615d7114a87bdd, 0x06c364440aa3b6cf}),
					decodeFieldElement(fp, [4]uint64{0x81fab3c8f2ec2261, 0x69927ff59ca0038c, 0xcf47520851e6d9e0, 0x250b797d72cab6bd}),
					decodeFieldElement(fp, [4]uint64{0x302dcc8b61eea7bf, 0x7129acef2f2589b1, 0xa6c4a826ba863937, 0x2557460f3563ba3a}),
					decodeFieldElement(fp, [4]uint64{0xcad4da3f4d798d46, 0x38f85e362c347d1b, 0x3b42374dad137285, 0x3bba0b91315c2ccf}),
					decodeFieldElement(fp, [4]uint64{0x043fbf2fee98f862, 0xf91018c5a7308d3c, 0x3baf4d083d4cf58a, 0x3d142ccf450a36ad}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6ad2455d58bdce3e, 0xa5355c8e761aa9b7, 0x953b3bbaca753eeb, 0x084c4be0982f6586}),
					decodeFieldElement(fp, [4]uint64{0x95e654303f1dbd20, 0xa5000cbe37cdc50e, 0x3e4b8810eacb3df2, 0x27276fe37af33d44}),
					decodeFieldElement(fp, [4]uint64{0x76b0a031b9944f3a, 0x0224f76317af701a, 0x4b65ddbebf7a841f, 0x37d6638ee89af69b}),
					decodeFieldElement(fp, [4]uint64{0x2e348a6e1c076a28, 0x3e709250ea9c7607, 0x96d22d414a39b91a, 0x27512b17303e8a60}),
					decodeFieldElement(fp, [4]uint64{0x456cac4f768efdb2, 0x591117a4b9e5f522, 0x9f832f6fd3c651c4, 0x3bb44499f2a8ee0f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xabb11a1b1a6be9bd, 0x82e8fdd1a11b1b62, 0x75641970078b0de4, 0x16d940a47bdabf02}),
					decodeFieldElement(fp, [4]uint64{0xa4e48e9f7a9fa3c1, 0x6f716f2a2973420e, 0x5a5e5fbb72f9a20b, 0x0d41183693aa1b47}),
					decodeFieldElement(fp, [4]uint64{0x6c540319f2cfb852, 0x0a0d88cf4edb6488, 0x04bc4e94b94c02e8, 0x1867304186c03c85}),
					decodeFieldElement(fp, [4]uint64{0x3d2f9b825643c652, 0x69ee6676ab7a12a5, 0x794ee407ac12304a, 0x1399f891788d717f}),
					decodeFieldElement(fp, [4]uint64{0xb2c00efb53f53743, 0x04a45ef0658d79eb, 0x056539581221f69b, 0x3bb25881d3ee5173}),
				},
			},
			spongeIv: [][]ec.Scalar{
				// Testnet
				{
					decodeFieldElement(fp, [4]uint64{0x487dff9d9a7b8b47, 0xefd4875a601205c2, 0xf56a378b007494ef, 0x195de8248e0dadc0}),
					decodeFieldElement(fp, [4]uint64{0x8c301588fd7a00c6, 0x19e525920db0a7f4, 0xd8183ab52c9c6572, 0x3d4694a7eb2e8bc8}),
					decodeFieldElement(fp, [4]uint64{0x8d4541df21f4397f, 0xc591fa386b9238f9, 0x161295fa575bc326, 0x38c8aa68b7f39c0f}),
					decodeFieldElement(fp, [4]uint64{0x0a804113bef86081, 0xab81c13710e24587, 0x0bf74936b3146110, 0x04280963ee233dc9}),
					decodeFieldElement(fp, [4]uint64{0xdf5e6a3d91f52f84, 0xa603bdaed4a3738c, 0x4ec2224e4cfd221f, 0x2b6f36b5f6cab0fd}),
				},
				// Mainnet
				{
					decodeFieldElement(fp, [4]uint64{0xd9e16576f3564838, 0x954abdf0a128121f, 0xc03d5b7763c11a09, 0x1083a7419b855dc1}),
					decodeFieldElement(fp, [4]uint64{0x768b7dc336ed8fb8, 0xeef214c1e0e754db, 0x54e0bfde984f4a4a, 0x012034271f5bbfb3}),
					decodeFieldElement(fp, [4]uint64{0x6e8f5cef55d7d636, 0x4415b728d56007a1, 0x0d00374c21f240f7, 0x34821014003cdf30}),
					decodeFieldElement(fp, [4]uint64{0x6fb9d5cdab103f63, 0x3a56d523e51afc9a, 0x73a74a3e21b95b4a, 0x1f3a851baa8d8ff8}),
					decodeFieldElement(fp, [4]uint64{0xd2a2c70a4e7618d4, 0x3857c852bc745ba9, 0xcbfbf39cda7182a9, 0x3ba058eb3edf61a4}),
				},
			},
		},
		// three
		{
			spongeWidth: 3,
			spongeRate:  2,
			fullRounds:  54,
			sBox:        sept,
			roundKeys: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0xf08bacee4938ac09, 0x339ccd34ef9feda3, 0x406b7eb265ba13b4, 0x14f6b220a6461ca0}),
					decodeFieldElement(fp, [4]uint64{0x92b80ddfcc823a49, 0xb9d5c5b829eaddc0, 0x6f7b22ad845425ae, 0x21d4ac7affa4f653}),
					decodeFieldElement(fp, [4]uint64{0xc4ec5e1bc819a55c, 0x2619a524140fa688, 0x8e8716adf4311d9f, 0x32233abf8550bb50}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x26ee7b1462904e39, 0x50d682613b7acf7b, 0x0284e560fb6ef2a1, 0x29b2958868a1e95e}),
					decodeFieldElement(fp, [4]uint64{0x6efb2611c9fa6fc3, 0xe1deb2c7f330db2f, 0x017303fbcd7f273a, 0x177a570ddbd6a7d6}),
					decodeFieldElement(fp, [4]uint64{0x2de22d0db066d240, 0x4c8fe0504dd4e1d3, 0x406020a7afc23ca6, 0x3378e8a91a3b3d2b}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa32c40c89d81b3aa, 0xd1eaa3db2e3c9d75, 0x246a4ddb1fbca3c9, 0x3c31e2eb15b94eae}),
					decodeFieldElement(fp, [4]uint64{0x014f2f422a023bd0, 0x6ec01a1a35ca11bb, 0xb9faa508869a90a2, 0x34ca08ca3d1f21c0}),
					decodeFieldElement(fp, [4]uint64{0xb698dec4992d7e1a, 0x126eb6b47a4162ea, 0xd43bcf08e3318db9, 0x3ed8560e1d53c6cc}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x14cd307ec2854ffc, 0x806ce76a0853d830, 0x492b13ba753506e8, 0x2f690c67e02badb8}),
					decodeFieldElement(fp, [4]uint64{0xbc8dc4d64fa37f3b, 0x2c27a8f6a9bd77ee, 0x65a4fa4851aa65c2, 0x082ea13f13fff25f}),
					decodeFieldElement(fp, [4]uint64{0xc6fe972b547807b5, 0x20dafd1ebda85c48, 0xdc0f5a2eea161bf8, 0x0c464d07e88d6bd6}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x070a58bb25e3ac31, 0x47b2f557bd68d69b, 0xb0a84e07a3c7e8b6, 0x0961b39b109a66a7}),
					decodeFieldElement(fp, [4]uint64{0x14417fa22c6e8503, 0x7d0f99859a7ad558, 0xb8a42746ce1da410, 0x016428fe792493db}),
					decodeFieldElement(fp, [4]uint64{0x76e3d9f48e0da28f, 0x538e2d703d04409c, 0xd2bc5e8e368dad37, 0x065243adb3707837}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xf4d65628001f43c0, 0x22c42c59485601d5, 0x3923c672db1c3de3, 0x26b9e1a39e793b10}),
					decodeFieldElement(fp, [4]uint64{0xeb76efc136b7a178, 0x567e96aa55d3866b, 0xed5a85b99eecee43, 0x17738ff236f1ead6}),
					decodeFieldElement(fp, [4]uint64{0xb87105a29c61baf3, 0xd35795b6391f2ba0, 0x80a647ffed796ecf, 0x00966870430b74be}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x2bae86fb011454c1, 0xf5809b4e1e3da38d, 0x9babdc58ef6b4911, 0x17ea856bd1de95ef}),
					decodeFieldElement(fp, [4]uint64{0xd8323dac29d2fd21, 0x232eafd3c9276a07, 0x51454c261a94b6b4, 0x0e8321b26ea859e4}),
					decodeFieldElement(fp, [4]uint64{0x06137345316630b2, 0x88c291d7f660b0af, 0x1881f5cd77efe1bf, 0x129cdf292b591c24}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0607f973293f511d, 0x68aa12e2c9948310, 0x17241df7ff24d191, 0x339b6badeadf2259}),
					decodeFieldElement(fp, [4]uint64{0x72c60a50001fc690, 0xe336ddb9580685b6, 0xa4275d63bc776cb1, 0x287e4795789a2e50}),
					decodeFieldElement(fp, [4]uint64{0x1e71cc793351de71, 0xe83013a07d69ed95, 0x96951b84fb700c10, 0x0f9059a35647f859}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x9a5ea9febe4f03db, 0xee13c54f2420a7ce, 0xc8992efcd0bb96fd, 0x262db723ebb639ef}),
					decodeFieldElement(fp, [4]uint64{0xc50d7495a057f3ba, 0x36160c9a225818e7, 0xd86266f2b6193723, 0x27640fbf6649e436}),
					decodeFieldElement(fp, [4]uint64{0xc5f9489e4a62d136, 0xc874b63d9bdf6fc3, 0x779633136b7cac3b, 0x38469f9d259e8860}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x3a88f094124a2f07, 0xa4ee933afed7ccf9, 0xe8a37a3f3598742e, 0x21d39dc7f5f1f85a}),
					decodeFieldElement(fp, [4]uint64{0x89117647af6c0b80, 0x95c0e739b2153b22, 0x9b73c8d4e53000fa, 0x1c01af397d9ce127}),
					decodeFieldElement(fp, [4]uint64{0xfbc5d9c901b44fdc, 0x110e3f4d58a97ba6, 0x3729b8fef69788bd, 0x3c83e0591432471d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x9167fde9f316995e, 0x02bed5472b932292, 0xadbb800e1b8d1a1a, 0x23ccbfeaae87f288}),
					decodeFieldElement(fp, [4]uint64{0xdde299fe82917685, 0x365ad1f02556507d, 0xdac98476c66e7b78, 0x06ca783a4c5661d8}),
					decodeFieldElement(fp, [4]uint64{0xc04081fb46e274ae, 0xc644984debdfee2e, 0x922823bc65dbcb4e, 0x2f7c6663f66417fd}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x7a404e50bc82b780, 0x6a94b84e53b87465, 0x09df84b6b0c2ea8a, 0x1ae757c4c83503e2}),
					decodeFieldElement(fp, [4]uint64{0x48dcf53e11dd9b42, 0x1c5e8dcd93be0815, 0x6171c720b4d46c55, 0x122a7092ce89f536}),
					decodeFieldElement(fp, [4]uint64{0x8e42eb53a0c25b74, 0xac084f5152cc0652, 0xf931459b0c5c8c99, 0x3d8af9c5d0333037}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1a9cf1df18a881af, 0x4442a58674c59d1f, 0x65fc770a6a624c7d, 0x19baa399ecbbc0f9}),
					decodeFieldElement(fp, [4]uint64{0xb6652c552f3bb0ae, 0x1cd9e79f2eb6114f, 0x1a72c5630fdd7ed0, 0x045b57796ed38c10}),
					decodeFieldElement(fp, [4]uint64{0xc026d4e8a4ba931f, 0x4a81d0ea273354e6, 0x213ff21e57ecfa4b, 0x309b4511608390b8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xe1643c8c2fc60782, 0x914ff5ffe929d27d, 0x306977a48fde88cd, 0x1957abac847de4b6}),
					decodeFieldElement(fp, [4]uint64{0xe9be963cd419dd0a, 0x5f667adcdea1af16, 0xcf5919e360df89a0, 0x0bae9b5a4b76dfc9}),
					decodeFieldElement(fp, [4]uint64{0xca4bec99ba896ec0, 0x9826eccf5e1e9898, 0xf25fcd5d32e5ed9e, 0x1fd9837ce45a7e8f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd7b111dfb80c8f92, 0xa27c59322fb4e58b, 0x0fee06724a2965e1, 0x2d55c896a670cfc9}),
					decodeFieldElement(fp, [4]uint64{0xc0278970c76e4c3c, 0x2d4f32c644bb972c, 0xb319662aa883f1b8, 0x2aae71971e21e449}),
					decodeFieldElement(fp, [4]uint64{0xc7d4372bdd79ca6a, 0xb12ec680f9869813, 0x32cbb2ee47fd5fc3, 0x234c0dfcd6aeb5ef}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4798cf6f5647105f, 0xcfa36da701968b49, 0x1af4abdb4050039e, 0x262da55b45ce2ad1}),
					decodeFieldElement(fp, [4]uint64{0xcb52db34ab960e18, 0xcd92b490c90b169e, 0x5e9dafa283013ecd, 0x139e7ddabf1b8129}),
					decodeFieldElement(fp, [4]uint64{0x033b9110f3e35dac, 0x00f062c24d72ad6a, 0x577b34ae7b84dd67, 0x1dbd9adefb2b233d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x24e2ac8a27b3d1bb, 0xd107984160cc5c55, 0xd99f8b5ebb00ccfa, 0x1675a7d815b57d47}),
					decodeFieldElement(fp, [4]uint64{0xb3d2d82634a49ea9, 0x9997cc034caa56b9, 0xae030c7ba288c1b0, 0x28095bbd12e81dff}),
					decodeFieldElement(fp, [4]uint64{0x93c2117b1130ec55, 0x0e247e4573d0fe04, 0x6f29e6f587115067, 0x0f83f5fd0774a734}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb5a390aa190840fa, 0x88ad67d1e2a44969, 0xe3ef71ff72c14547, 0x1099ba003b7a3c70}),
					decodeFieldElement(fp, [4]uint64{0x4d21b0d9322d725a, 0xbff6be0dd2417ab0, 0x5db16a3df64a6b6b, 0x32db3e65d925e5fa}),
					decodeFieldElement(fp, [4]uint64{0x8b026aca6aa63eb4, 0x6b82feea9eb24739, 0x46d8e6c74170f902, 0x2dcc4d0495b35ca0}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc32a758010a9a148, 0xb9895fdfebce1146, 0x36b3c868003ddfa9, 0x1e795dcd3d2d0ed0}),
					decodeFieldElement(fp, [4]uint64{0x961062a6a5362a8d, 0x1dbd28466c90b985, 0x8c3fac5c3cdbf794, 0x07c92af90335e981}),
					decodeFieldElement(fp, [4]uint64{0x480430af86b5073d, 0xaecbe2439aa047ac, 0x6b0472bfa0788d2f, 0x17c9e280f9e18eb0}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x23b129a79ca66f55, 0x80d30d13d9c1dfc9, 0x43fdffe26d2b044e, 0x23e969f4a44126b4}),
					decodeFieldElement(fp, [4]uint64{0x3b91f8b9dd3d7028, 0xfd1aabefc28d80cc, 0x5f20563c432e6553, 0x177282761a9c465f}),
					decodeFieldElement(fp, [4]uint64{0xf84ed91dc8c7f579, 0x6868443afd78a167, 0x5d5a97f345534ec8, 0x3af4d962e318268d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb62d98440e1239d0, 0xf94069c5dff281c6, 0x0e8ea8033902064a, 0x2be53bbdf2f06db0}),
					decodeFieldElement(fp, [4]uint64{0xf66b6326561c2604, 0xc1a8dfb3c530ed2f, 0xa6f7e2dac1a6bb0f, 0x21735ab0868dc436}),
					decodeFieldElement(fp, [4]uint64{0xce5606aed4618d35, 0x33fbe78cdd5ca65f, 0x78cc5ecd6051ab65, 0x0ee6c71a2be1b77f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x46d480ca460394e9, 0x80a6857bf107623b, 0xc7b110acb060db97, 0x168988b4a53904e7}),
					decodeFieldElement(fp, [4]uint64{0x58fd265e9e0b8afa, 0xfe3e34d451a773c7, 0x9b4e4f8cf072c52d, 0x1caca8e40be72281}),
					decodeFieldElement(fp, [4]uint64{0x9a3db0cdfc88f9e9, 0x01ce58eaae63e372, 0xf3ddd96060b4ae1b, 0x35ee65873584c5f4}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x8442b780ebed921a, 0x7b4cc34f06b2bcc5, 0xe70aff29b148a73e, 0x0c65d95a02555b38}),
					decodeFieldElement(fp, [4]uint64{0xd375efbbd60bf98f, 0x172652ccfb21531b, 0x2e53d7cbde25d7f6, 0x07c8f90c4f7f0a21}),
					decodeFieldElement(fp, [4]uint64{0x05b7b70944855db9, 0xbba80f60209a7509, 0x521069a2e363b8d8, 0x11266df9801ddb3b}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xa61a1849f8cd7c05, 0x039bb3182309a45c, 0x0d1da23cdc5dd4c5, 0x2f16b084ba41e5f4}),
					decodeFieldElement(fp, [4]uint64{0xfcc27ce5050fc57c, 0xd201b427158ebc0b, 0x40d45df6d43d6186, 0x34a56099716cd5f9}),
					decodeFieldElement(fp, [4]uint64{0x200ecbe0f9823aa8, 0xa61040916715ea23, 0xc6061f284799f6ce, 0x1669b36a0bcde89c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xbdcb414d4a4f30f0, 0x997a57cad26f0446, 0x0cc9caa792667009, 0x3ff31dfa1a9dd9f7}),
					decodeFieldElement(fp, [4]uint64{0xb1ac312c187fab08, 0x091fdbc3c37e43c0, 0xeb39b9b3ba119e05, 0x31bbf9721f7ccd75}),
					decodeFieldElement(fp, [4]uint64{0x8bc6575f71dce0f4, 0xa7aa44e4e8ac72cf, 0xdfacef7e3e579ebe, 0x27e0f931448e74b8}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xbc7b3d0bfe04ead8, 0x7674e98a98f3c9aa, 0xcb30b22e6a5f0614, 0x07123068e61f630b}),
					decodeFieldElement(fp, [4]uint64{0x0807daab6bcb69f8, 0x8aeb523c9a5d7228, 0xbc9c416985066c6e, 0x0f47a5f0687ac15c}),
					decodeFieldElement(fp, [4]uint64{0x30824ea7095b2e5a, 0x5b07fb38317a10d8, 0x86481a17eb3c9539, 0x3af152ef369f4cfa}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc01c40021c8f40da, 0x6c8894ba234cfebc, 0x7bc7130c87511177, 0x06a0c676702ff5d9}),
					decodeFieldElement(fp, [4]uint64{0x6b7828b93dc76c68, 0x87e0cd44860af080, 0x86674c834249a48c, 0x152669c809a8f6dc}),
					decodeFieldElement(fp, [4]uint64{0x01e097e72965aff0, 0xad510da5d8996f81, 0x6990f4737c9d1943, 0x1b04ba3b0bf98efc}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xb0dd7f0c23facdcf, 0x955aa01ee35960e7, 0x70f3410d0ed356f9, 0x1fd55ebbf14ec073}),
					decodeFieldElement(fp, [4]uint64{0x8ef03e4fc75306df, 0x4768dfb26cd21cfa, 0x6728a83f1c7ff56a, 0x155f1f461f108ce7}),
					decodeFieldElement(fp, [4]uint64{0x79459ac1386ea3d3, 0x88596d343fc724cb, 0x2f1ad94368253e3c, 0x1bf280a45948949f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xbe5aa643f2242a69, 0x69a33568d91b7434, 0x181e72505d6b4b20, 0x1565ebed3c4f33a1}),
					decodeFieldElement(fp, [4]uint64{0x540410a6eadb956b, 0x812019ae96417f9d, 0xb7741647d266a63f, 0x305e31db1424f7e3}),
					decodeFieldElement(fp, [4]uint64{0x8da01cf84824b078, 0xe6b20490345cd180, 0x563cac5d4e7c19d7, 0x1aae16ddcc32db7d}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x81060b1353bcc62d, 0xffad64213b206d17, 0xaeca98f90a16d5ee, 0x2b75c12198cef1ca}),
					decodeFieldElement(fp, [4]uint64{0xd05efd8b1dda5e9d, 0x530d354177cf09bb, 0x00b19eaef58eba2a, 0x3f00038fb23190e0}),
					decodeFieldElement(fp, [4]uint64{0xab5cec35475b29f7, 0x96a5159de41fbe8d, 0xbb13d1176a35af2e, 0x370032aec9393d37}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6b336b723d1bf83f, 0xf161ac2903ddd626, 0x6482fba5a05e7804, 0x036ef99996efe312}),
					decodeFieldElement(fp, [4]uint64{0xb1b2cd9e778a5add, 0xa1700a790f965c4e, 0x7c76c42aa37173a4, 0x1ec94787e05a214a}),
					decodeFieldElement(fp, [4]uint64{0xa8d5c7ea1d78491f, 0xd1e5bf332cdb74cf, 0x252f44f9078eb733, 0x07b98f024755340b}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x6ee151362bb7d516, 0x44374912ab3309d9, 0x9da100c570c7eea2, 0x1d1f2792532aa0d2}),
					decodeFieldElement(fp, [4]uint64{0x761eac9357b16f8a, 0xc3017c4bdb1df982, 0xa6ed42706875c4c4, 0x2ed605d75bcbf76a}),
					decodeFieldElement(fp, [4]uint64{0x889ac236b8855c0c, 0x8ecf878007227244, 0xdea9c6cf4c3de97e, 0x1c01c7672a759fe3}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x34c6b900ecf64330, 0x73f8bd5676d8af44, 0x168112bf630f265c, 0x02a6a3622a367e19}),
					decodeFieldElement(fp, [4]uint64{0x790c8dfd552ccf28, 0x2d765be385ee7427, 0x64e78fdd06ae4bc6, 0x2a99d6e914bce640}),
					decodeFieldElement(fp, [4]uint64{0xf8d509bd15fa38fb, 0x5d4f24bb5e8428f3, 0xa0b3e5eddf95593a, 0x26efd6e254d64131}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x1ea70287c0e26633, 0x2ea47043984bfc96, 0x5fdad3583797bcc9, 0x18244010b97b0c37}),
					decodeFieldElement(fp, [4]uint64{0xb7361d7706f64a19, 0xacaa8fe7216b1c41, 0x371186ca504e5e49, 0x014498fa309d793f}),
					decodeFieldElement(fp, [4]uint64{0x93179fcb30993cc9, 0xd3d4808aefcab4c7, 0xdc209837ff094772, 0x227ad6ab6947e58f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x3771b591c4c44a8b, 0xf8265c64b8268201, 0x4dbd0be9da1cc978, 0x1bf430ee1de4c02e}),
					decodeFieldElement(fp, [4]uint64{0xf4ec83bd3294dd26, 0x2c84c735ec4e7f18, 0xdf8b20066d0db2b5, 0x04c160577b51d12d}),
					decodeFieldElement(fp, [4]uint64{0x2e818cfac1e6c560, 0x2d929a35051a9430, 0x4fe9863ac2176e1e, 0x330fdd57c7dd41aa}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x26b457e600e42965, 0x0e349cf0592c4031, 0xc8d469a38ec04d65, 0x3756fa53bb926a44}),
					decodeFieldElement(fp, [4]uint64{0xd4544a499d53a744, 0xc9a80a07ff8db49b, 0x58b3ffb887dde5a9, 0x3e4921dd4655db80}),
					decodeFieldElement(fp, [4]uint64{0x5d42ef0ed58d906b, 0x70297229033b6048, 0x4f898532e7e8da76, 0x10b5a3cd4189bb9c}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x586b84c170c90550, 0xd3a4d463c1598749, 0x51fbc05f2629ef02, 0x1e59a60812d45148}),
					decodeFieldElement(fp, [4]uint64{0x60e97261369840d4, 0x1edefaba4834206c, 0xe0e187bd881e3341, 0x2a78ce41e3a96b59}),
					decodeFieldElement(fp, [4]uint64{0x1cc0ce525d9619ca, 0xcf14418ce9f3f015, 0xaa862ffd79ff5309, 0x187ded0cacfe80df}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xc3dbb44fe0468862, 0x61d967fdedd73c19, 0xd1f3cd8eaa9b55f9, 0x0736db715011b56d}),
					decodeFieldElement(fp, [4]uint64{0xe06f70a6bf3c5211, 0xbaf084f7526133ce, 0x40432588688238a0, 0x113e3f81afc4169b}),
					decodeFieldElement(fp, [4]uint64{0x20d94b8fb0ee9d03, 0xd058e8dbb08c9067, 0xff63acf2c2d908d7, 0x0571dedabcacf6e1}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xdb2289c5648f6453, 0x44aca60d6f60a2a4, 0x31bff19e4be2b46e, 0x2805399d701ea637}),
					decodeFieldElement(fp, [4]uint64{0x4dd5108b64cabd77, 0xa0f644b8ae2844a8, 0xad166de7aa7e8071, 0x150b2b6a0a408f27}),
					decodeFieldElement(fp, [4]uint64{0xb648c596f7e342da, 0xf8adb6dcd6164132, 0x1d7a889e824d9c69, 0x37a0e54cf77999cd}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x608ae12dd0c5e463, 0xbf02c2faf94ada0d, 0x4b79a92daf1496fb, 0x3fe59f54d4dd7b43}),
					decodeFieldElement(fp, [4]uint64{0x09e9ce09f9781eee, 0x9260f9b7a32c8404, 0x7b6d04e5cb5659ba, 0x037e58d6c2a9c951}),
					decodeFieldElement(fp, [4]uint64{0x68e24f8b287424b8, 0xaf3688426218b062, 0xdae86d12dd4489f8, 0x1bbab6ce4ae86d00}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xaeb271ac7b735553, 0xab21cce089ca583d, 0xcbd99a83e1a9154c, 0x0d1c4af0296379b4}),
					decodeFieldElement(fp, [4]uint64{0xb6e0d0d5b472ff64, 0xd46317b3cab0623a, 0xd2a96283d42c09bb, 0x091865bab3e2fe86}),
					decodeFieldElement(fp, [4]uint64{0x81337b7a52a6ac9e, 0xea25b269541cc6a2, 0x6df940814ef8b598, 0x16dc43b7a60932c5}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0aab3090b5c77120, 0x4e2499f4bd3c66f9, 0x66ae6e7f31fca09d, 0x3fe516b2434aabaa}),
					decodeFieldElement(fp, [4]uint64{0x97ab469167a206d4, 0x183d8a741d81edbb, 0xdab876e754313b64, 0x0e3a179e34d5252f}),
					decodeFieldElement(fp, [4]uint64{0x0f9b1f536a630e38, 0x45d35baf73723c1b, 0x072073327cd08f38, 0x085394ac24a2fb09}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x4bc8d2a62ae0ade7, 0xb8f61e775dd06264, 0x4946931607cfa754, 0x389367d966a9a7a0}),
					decodeFieldElement(fp, [4]uint64{0xb96144ce5813d0d4, 0xe1ec84838b51f52a, 0x0c555cb9fcf8a337, 0x21bad42ba0fb1aa6}),
					decodeFieldElement(fp, [4]uint64{0x78465f49f3e692e1, 0x6704da6fbe7704d4, 0xa3cc6852e79249ad, 0x2036d9db2ec5e6c5}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x5918e586de4d0e33, 0x8db2ae8593184055, 0xc2dc19119e972590, 0x2d67c1919959aaec}),
					decodeFieldElement(fp, [4]uint64{0x4037d195d8a36b16, 0xdd54628c366c1bc4, 0x9cf82c9b3b607197, 0x0b26c92bbbf07b9e}),
					decodeFieldElement(fp, [4]uint64{0x60ecd3446fa7b832, 0xc28b96e72ae96b00, 0x18bc4d0d9bffb92a, 0x030ae8709a622332}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x49fac3d06502f02e, 0x3d2bd3ea3d0c5580, 0x839c14be1c99bccf, 0x2adf11b3048b6e86}),
					decodeFieldElement(fp, [4]uint64{0x8e1693bffd553fb7, 0x89cf1c198cf7db4b, 0xee564912ca6e5ad7, 0x118a5f449b5ad82f}),
					decodeFieldElement(fp, [4]uint64{0x39df129223d43427, 0x8c13d83b6b2dfcb3, 0x3e6bb9e1942f024d, 0x05b000684fc3f065}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x53c53f9ec45b5887, 0xcada324d7864406e, 0x3a4e2c6caa214e43, 0x2f0d34dd2321bf63}),
					decodeFieldElement(fp, [4]uint64{0xe9d5f616f17e2b5f, 0x02f906b52b2ee4c2, 0x9e7c87a2444ed47c, 0x228cb81275c9a001}),
					decodeFieldElement(fp, [4]uint64{0xd974e7e00624c9e6, 0xfdd9ef5f09a64875, 0x689ca178f70d6f49, 0x391c22302e9157b3}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x0fed9ca072d4567b, 0xef387bb6c75c8b78, 0x09ce12c96ad04246, 0x3f65ae92f8ac084b}),
					decodeFieldElement(fp, [4]uint64{0x778371041d4e74f8, 0xe9a4e139d42079b3, 0x5999f991bb832dc9, 0x3c0e0540f65d7b13}),
					decodeFieldElement(fp, [4]uint64{0x76a48981f693e57b, 0x9341964ef0643b39, 0x927307f9a2c50ac9, 0x3552bfc0a44beafb}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x18e0b3e3dc1ea52b, 0xcb515ea6cb40b34d, 0xffe8e2fd3741991e, 0x27364cf2561ad921}),
					decodeFieldElement(fp, [4]uint64{0x6c2b84b7e32312fe, 0x3d6475784d4fb83b, 0x8b44f264c4815724, 0x303387de294c2ea3}),
					decodeFieldElement(fp, [4]uint64{0x81078adafa434790, 0x5cde66ce444aa67f, 0x5e7ebc1e8f132038, 0x1bc1149a71db21d1}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x9cba1a1f254466b8, 0x05dd955d056ca490, 0x37b0621b4f65c810, 0x161e1228df934619}),
					decodeFieldElement(fp, [4]uint64{0x49efec83c4520fa2, 0x71955732c09a915d, 0x6f8a2a7b653f5206, 0x277ce2b942082ad2}),
					decodeFieldElement(fp, [4]uint64{0x35e1ca05049f52da, 0xf1203899d33cbaf5, 0xeb51ec0f549304f4, 0x232c85036ee970ee}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xdfa1a541f3a89c43, 0x41769272b052c154, 0xa77e9dcd36910d26, 0x19f14b55420a11dc}),
					decodeFieldElement(fp, [4]uint64{0x42b9df1a82e03d2b, 0x3de94fcbb20ccc80, 0x365eec97d95577b6, 0x0f28e797ce5d2cde}),
					decodeFieldElement(fp, [4]uint64{0xefb42b0973afc50b, 0x8b7c8982d92bfcfe, 0x15c54defd9c72711, 0x0419a1b8a70929cb}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x72848bd2017846aa, 0x1f6891b8a2dcc99a, 0x8a7376226e57edf1, 0x1245a8a9321119a6}),
					decodeFieldElement(fp, [4]uint64{0x7319d595b8fff55c, 0x58eee4986e135c0c, 0x2fa0737f2c7a3f80, 0x119a2e6e5d331067}),
					decodeFieldElement(fp, [4]uint64{0x5ff38ed35585b92a, 0x8a031ba05e2a08f8, 0xaeff38dd1383717c, 0x1ecd220af17fca26}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0xd691b718c35af134, 0x689acfb1a3e02eb2, 0xdc2f04c63581183c, 0x0b3a2ff9191280dd}),
					decodeFieldElement(fp, [4]uint64{0x21c10c51b71dcce3, 0xff1d9b5932560eea, 0xb99f747e99fedc1c, 0x0231409ff374eb9d}),
					decodeFieldElement(fp, [4]uint64{0xc8b54acf78d9dd29, 0xca29a75f92adf8eb, 0x7c02293302db738a, 0x1b4c09a6dfa71947}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x2c55e04e4e4b5ed0, 0xb5e27c5b4d13e34f, 0x21e957242fefaaaf, 0x313189242c80bf78}),
					decodeFieldElement(fp, [4]uint64{0x5005b229e52c6c2d, 0x198f54698a84de60, 0xf3f51d50088c325a, 0x170d04de5e7a55ef}),
					decodeFieldElement(fp, [4]uint64{0x6ec48e38d8ada712, 0x9ca7d3f4394d2486, 0x99869db91d7be0e4, 0x0883e4e20e03eccf}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x32cd645af53ab8ea, 0x9ff1a04eb3c8159f, 0x5312be584462f4b7, 0x2d73b5cd97e57129}),
					decodeFieldElement(fp, [4]uint64{0x7e8766a7a46e7e88, 0x9cce401c7f37364a, 0x28f75b4b3fbc56ed, 0x094786b228edd040}),
					decodeFieldElement(fp, [4]uint64{0x0236fd6055e1716f, 0xa83689fa08b0739a, 0x88c28839c6af604a, 0x0a790cd6a4d3fd31}),
				},
			},
			mdsMatrix: [][]ec.Scalar{
				{
					decodeFieldElement(fp, [4]uint64{0xcfe2eb225c7cb8a4, 0x2f2e2a3800cca3c2, 0x8b1043bdb1f7aa01, 0x24676611eae68e61}),
					decodeFieldElement(fp, [4]uint64{0x5eabd5122097af3e, 0x4fcc314613ba39f7, 0xe1d8c4d0220acdd4, 0x27f1b7533d7c67ef}),
					decodeFieldElement(fp, [4]uint64{0xc4943f0e6a65eeba, 0x1cded1f1b6040054, 0xf9c228f850870714, 0x395cb23c75634268}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x46b32ec2d6958a48, 0xac5eefe2c39b1ad8, 0x53e24909bd7d76c4, 0x2f6aa8c87ac7141d}),
					decodeFieldElement(fp, [4]uint64{0x5232e32f360a2824, 0x4a573c51d4688988, 0x3152f7d17150b9b5, 0x2d36ebd2b4f85251}),
					decodeFieldElement(fp, [4]uint64{0xa4d436df31c74c04, 0x7fcb38c991e38db6, 0x45f16ff3c010cfe7, 0x332b0a7fa8b88a5f}),
				},
				{
					decodeFieldElement(fp, [4]uint64{0x13b180baad772788, 0x90583fb73b469d35, 0x2a659f3d2fac6bff, 0x293575baf7ecf110}),
					decodeFieldElement(fp, [4]uint64{0xbb574ff75c7a5344, 0x1fe49f83a3f5ff55, 0xe45dd6a3f80710a7, 0x100b6d838357d6d0}),
					decodeFieldElement(fp, [4]uint64{0x8001329098a0b3ce, 0x15f44e53264e3df8, 0xfd13ec7cf677b9d5, 0x2b628486e35994c6}),
				},
			},
			spongeIv: [][]ec.Scalar{
				// Testnet
				{
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
				},
				// Mainnet
				{
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
					decodeFieldElement(fp, [4]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}),
				},
			},
		},
	}
}
