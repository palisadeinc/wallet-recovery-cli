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
	spongeIv                                      [][]ec.Scalar
	roundKeys                                     [][]ec.Scalar
	mdsMatrix                                     [][]ec.Scalar
}

// Executes the Poseidon hash function
func (ctx *context) permute() {
	for r := 0; r < ctx.fullRounds; r++ {
		ctx.ark(r)
		ctx.sbox()
		ctx.mds()
	}
	ctx.ark(ctx.fullRounds)
}

func (ctx *context) ark(round int) {
	for i := 0; i < ctx.spongeWidth; i++ {
		ctx.state[i] = ctx.state[i].Add(ctx.roundKeys[round][i])
	}
}

func (ctx *context) sbox() {
	for i := 0; i < ctx.spongeWidth; i++ {
		f := ctx.state[i]
		t := f.Multiply(f)
		t = t.Multiply(t)
		f = t.Multiply(f)
		ctx.state[i] = f
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
	}
}
