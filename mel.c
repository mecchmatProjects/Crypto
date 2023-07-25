#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

//200000000000000000000000000000000...3ffffffffffffffffffffffffffffffff

#define MIN_DOM "200000000000000000000000000000000"
#define MAX_DOM "3ffffffffffffffffffffffffffffffff"
#define MIN_DOM "000000000000000000000000000100000"
#define MAX_DOM "000000000000000000000000000ffffff"
//                   599999999999999999999999999a9
//                   60f4d11574f5deee49961d9609ac6



char RANGE_PK [][67] = {
 "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
"021697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5",
"031be68a5a028f2601d0e80d468c344ba331d611b96c358b6032e8b4da0547fc11",
"03605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479",
"02e0392cfa338aaf2f0b56c563e3e5e67a5d5fefe3388f85d90c899da20f0198f9",
"0362d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d",
"02b699a30e6e184cdfa88ac16c7d80bffd38e2e1fc705821ea69cd5fdf1691fff7",
"0280c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f",
"0391de2f6bb67b11139f0e21203041bf080eacf59a33d99cd9f1929141bb0b4d0b",
"037a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb",
"02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
"03d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9",
"025d045857332d5b9e541514731622af8d60c180165d971a61e06b70a9b3834765",
"02049370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963",
"03f8b0b03d44112259f903b3d100e3950d980fdde9c7e85701c16baedc90235717",
"0277f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74",
"026eca335d9645307db441656ef4e65b4bfc579b27452bebc19bd870aa1118e5c3",
"03f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530",
"0229757774cc6f3be1d5f1774aefa8f02e50bc64404230e7a67e8fde79bd559a9a",
"02463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b",
"032b22efda32491a9e0294339ca3da761f7d36cfc8814c1b29ca731921025ff695",
"02f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247",
"034fdcb8fa639cee441c8331fd47a2e5ff3447be24500ca7a5249971067c1d506b",
"02caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1",
"02bce74de6d5f98dc027740c2bbff05b6aafe5fd8d103f827e48894a2bd3460117",
"022600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120",
"0245562f033698faca1540cbc9bf962cf4764c1ef4094ee4b6742b761c49b46d3b",
"037635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435",
"0301257e93a78a5b7d8fe0cf28ff1d8822350c778ac8a30e57d2acfc4d5fb8c192",
"03754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18",
"03108443b948d1553584a271333f7fbd043c4d66a91706edecbf07f6894c04f299",
"03e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8",
"03bf23c1542d16eab70b1051eaf832823cfc4c6f1dcdbafd81e37918e6f874ef8b",
"03186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb",
"03079264c4b4bfcd7fe3a7b7b92b6c439f3a5b3abcd29189bf7b54d781ff03d722",
"03df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f",
"0270e6b44a2ac6083ab673bacb5cb7ca554b795b416e702c1c980bb7b87c78b8e9",
"025edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143",
"03c00be8830995d1e44f1420dd3b90d3441fb66f6861c84a35f959c495a3be5440",
"02290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba",
"03a8f2c94e19d9d829ecb4b17f84f42d8c1e988d693df4a1fb659032865ff5154c",
"02af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45",
"032773840fcf4e9e459c052cebbfbb7e9dfd6b072c4fbb8d476e37b93c5c478840",
"02766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a",
"0296516a8f65774275278d0d7420a88df0ac44bd64c7bae07c3fe397c5b3300b23",
"0259dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e",
"032ddf7bbcfe114e807efe354db9f95fe70e7e555bd9114950bb3d3d987058c8ae",
"03f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8",
"03e9623bbef1bf90ec0d7c744ed34659f010e6e638637161270ecd31e14f87f62e",
"027754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c",
"03e35bc6bb1b05b2130a37c28e771c6cb4be89b397b454c8b59e594fecc13b59df",
"02948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519",
"0287c01e27d84da2dbd3330a7f05a58614a1ecdbabdcfccd39e5626baaf6812379",
"037962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab",
"02497c83c39c76e56d070fb906bced44099de2d0e222575f22e4749682de46eeac",
"033514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca",
"02a8af384e794930e63d81d3e1ef66cdab16d1cfda1b054da5f7086353a80c44fe",
"02d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf",
"03eb49fd9f510469f4fe540e4b0664410f216cbbc90d97aed62af2e606110cc919",
"031624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610",
"03de1d35cbc6308cc5b435db84a21605a7d3a6172d6511c68bf6639d49c8704818",
"03733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4",
"0284df2e6e5e84cdff24120ca18648961ac134bcd7d6f35919bf6dcd5710e682f2",
"0315d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c",
"033f0e80e574456d8f8fa64e044b2eb72ea22eb53fe1efe3a443933aca7f8cb0e3",
"03a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940",
"024752f8548620831139bf1c39d65f194d191110fd2e9122abd637ab63ef91e5b4",
"02e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980",
"02ed3bace23c5e17652e174c835fb72bf53ee306b3406a26890221b4cef7500f88",
"02311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3",
"023049f7ffc71d744bd9bed6f42dc6a28974e3a1b9d30671f800e5d46389103c7e",
"0234c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf",
"021880c9ad32fbb07e1fb52a688d9d6fe6db0df90ecd4c9483203f636ee00926dc",
"03f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63",
"031fc757d383e4250772310db34c1e79f3888043b17bcbe91490c7f04f8accb725",
"03d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448",
"037e660beda020e9cc20391cef85374576853b0f22b8925d5d81c5845bb834c21e",
"0332d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf",
"033bb9aec1f1eb9ec7fa735fc4fcd0ab7c7b00f024a9728087f745ddaa42583d11",
"027461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5",
"02bc82dd73e5161dba0884a36f2080d682ffc274bf62fca8f9eb0aadf82a8d733c",
"02ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6",
"02b74f0c165b4a943593cc339096d66ad588d6b130b16695e5bd95ec557a93eab5",
"0316ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5",
"03fc6040fe245682cdf81eee193a3af355ef6cc374ce1438469306fe7f8957f489",
"02eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99",
"02a7c0ea7395d8785253de84833ccffdb31dc81f9c32bb84a53ec1775d0fadae00",
"02078c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51",
"02dd5ba67cfb807824bd3ff25e9d1667fa89e7020e8e0becb79caa00f574adc826",
"02494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5",
"02139ae46a1133f1f9d23f25efba0f6dd87bf7ddaf568a5fb9e0a3bfda73176237",
"03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5",
"02f90b89d53bdc724a685bb8c12419bbf5b8ffea50ec08422a9a7b09b1029471e3",
"03c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997",
"026df7b5a7a126a6112e1e0ba01ad1a0f89f055dd3c1c7e5336938ad32c494b319",
"02841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881",
"0234ff3be4033f7a06696c3d09f7d1671cbcf55cd700535655647077456769a24e",
"035e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5",
"039dda94404337db1474e67f1d7052f398a0e70ed205c5e94d6e731b06c6f51cd8",
"0236e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66",
"028a93046d22897b40361bcd154301ff4b7ed3c170c45e44d445d2ae2ae38947d7",
"020336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726",
"02d5f66020bdd383a875e8b46dc5a91925f17d3f1f5eeafb4e2b1f39bec59b9618",
"028ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede",
"03f25f6e271e231dfd5f5f8d2aaf30fc6dafe835feca1575e93f667f69d0d97018",
"021e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94",
"020f1dd626b97220199541a803535b09dc6f0328bc6eda337b5ea937913ccf1095",
"0385b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31",
"039358bf4e626ce79a888c0a54ce408b48fa4acb89cd7d9487b92d2f1129289fa9",
"0329df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51",
"02ef68a2c7ad33241d6adc31b4e7830036b5e571af914fe014c9f81b66ff472adb",
"02a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252",
"028e3d1248c7657211d20291ce1798f490743f1bc852858e32d7efe2315fbc7671",
"0204e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5",
"037b732af34077f33108a0e679d9eea6a81cf5e707c8f3050d5dfb298429952152",
"03d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b",
"03ecc99b0cf89ef1412718197ef17ed0876f02c24fbb10ae46df051b79da14b6c3",
"03ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4",
"031f6014569d1203ae0c128ac00a41097609b16386bde7f857b908ea95e5eebbef",
"02af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f",
"03e19d8d416b28eeefb603b7d5153773222f127b76ff24d7b8419eb6997dee8d17",
"0200e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
"029ea5c218b98cc990bf7257c3b588e75b4a03a9c0107e1d638e7b0a261f997190",
"02591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246",
"03a8be67d40815919c5f13c7cc84c166d55e603eb6750077acd7a17c18f15a3699",
"0211396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984",
"03915050c28c39ebfd36ecbe198e90fe71a53573822a6e94b30f734afb0a29f390",
"033c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a",
"03308913a27a52d9222bc776838f73f576a4d047122a9b184b05ec32ad51b03f6c",
"03cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030",
"03fbaf4eb5bdf8fe9397a3b8bc51bfa27183ff4ac34a966eb822109700780a7943",
"02c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197",
"03f62885ce55ff7be291dd96717159e106b77beeb53920db82a218a7bda715e7ba",
"020c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593",
"02a5822bd06c673e21b41f30c4efd7c49109f00c12cdc12c5156835fe50c9d3205",
"03a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef",
"03328ba6c70c404497a663505914704a7b695331569d729745baa1f1cdcbf2d359",
"02347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38",
"02f9502d540ca7d5ab09ea89e83889fa4bcd0b27f7eec5752f4fa07b1b19160f3b",
"02da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a",
"02c4f942ea2b52a8cef06e95d0665a4073d9c41961f668fdb68464ab4070ab2b7a",
"02c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111",
"0269317694d15b16c548fc20ec98691ed6838230a85b762e92fa4f1bc1da40f082",
"034e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502",
"0378a891aa2234a498896a193ed088a2b68fcae82788f506a0f3287432beb31db2",
"033775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea",
"03192e787021b1e83ead4572c55b488607dcb079365966c5437632c5c33e4cb721",
"03cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26",
"038267f5f35e78f30dcf58f7bc65a2514d0c8c0ac8d1f6b99374818ee88f5e524f",
"02b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986",
"02a076cacf92cc467c94ed72da5b9961395dacf1a224b157559169e4ea2b19a602",
"02d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e",
"034265bbaf8d442ac5162aaae1836a64aab9e912769ef3393f395681815f5be39c",
"0348457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4",
"033e805fa563758c7b2187ee0a7a4e2503495f3686c9351822b054d3844f1724c1",
"03dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda",
"03296eef5bdd483af1ec401a7fa0f5db8b75a7adb1b159624075f3d8ef294845f3",
"026d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859",
"0232c001f5785688f62416f0ae4ed51ec85d8db3a2dc56b8b1e63065b098bbae2e",
"03e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f",
"02d7a0da58d01dc635812ddf64d99c9aeae783c797d7cd204ec7b750f733ce1752",
"02eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c",
"03838ed2eb98f466853b4ab50f6b1030ce1d8742af3a39049ad0f9cf8031bdc863",
"0313e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942",
"0221c76dbf7a8d075a88b426221796035964f08ea3aa575d8f5f2d7ca5d86e196e",
"02ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a",
"0293e651f2d3ac2659e38b59ba5857b83cfe3f31125f3bc5bc6a0c81bd90877ed5",
"03b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80",
"03cd5a3be41717d65683fe7a9de8ae5b4b8feced69f26a8b55eeefbcc2e74b75fb",
"02ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d",
"036c0d1f1784e47ff04108c1d9049df6b3658aa6490ef4ef1ac1e4dbfd90ac0427",
"028d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1",
"03da9b9e9ab699c11cef8b8cdbd452f7c5ca6dd9da7a9efa19acc0a89758554b6c",
"0352db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63",
"0352520de6009c7e49f080ea4c21a2ade2d2f58220c30a7cb056fc4c098ad30369",
"03e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352",
"027d86781855db1b17d7ce3765816076eba7163cb9fba082bb65348f778db0e595",
"027f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193",
"0359ae134c1a41cfee81c5c2cd51ac727b4e7759552d729e07b25031df15661815",
"025098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00",
"03f4a0caad9ad209925131b1389effbbd28615402eb31f2c082cf6531fd68befd5",
"0232b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58",
"02b40226a37a1a586d0b360ad75ee73fabac67947361320882a8f9e0cfb9746ecc",
"02e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7",
"0354bebc996f6c2b7c52ac321ea930afa666c2f828ca99facc577e0ffa43b4f3bc",
"038438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8",
"02cea8d97ae24caebb2bba4eff99c743dccac732be31e1b61434d667b8fad96201",
"034162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e",
"034b24649ac96f264fd12ef9ca0a34b068f84b6f6249ae3d7dfc9caa19ff32151e",
"023fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d",
"02bdc6c1b0f061c563243061575dc28b48a562847bec1b88b6f600bbde5b2c74a4",
"03674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b",
"0308bc89c2f919ed158885c35600844d49890905c79b357322609c45706ce6b514",
"03d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f",
"02714651a9cb4af14c78ac98661e39723d234d56537053d0140f08670f188ce2bc",
"0330e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6",
"027e62469c0893fc1661fa0449250cd2a57558b9e8d46130c125149eed98fe1249",
"02be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297",
"020639863c5cf03696867960f4f378473fafddfed53ea145226b51046bf16e839b",
"0293144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a",
"037d54261d569c7330a5b943abdd4a0d7f2fb1f35ea3adc41f422049a122517961",
"03b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c",
"03b35511d67e63fa6552db740b48aba6d230c21799e65a6647a5cbfc789ef0184b",
"02d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52",
"02e485be3daccabfab0e0ca7b596da918d7f0107d535274c949683baab330bff95",
"02d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb",
"030659214ac1a1790023f53c4cf55a0a63b9e20c1151efa971215b395a558aa151",
"03463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065",
"02ddc5310f00582ac848494b9dc41ab08676545f84205e6a2a008fef8516060dfc",
"037985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917",
"036a843ba43c244f89a8f86c708c25f0e14d8e2df756ef139df3ed516ed7c504ef",
"0274a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
"032e34552aa716aef75edf6a1f8a10dff8636478cbbff1713a5fc0da4813704a08",
"0230682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3",
"0200136933174bc388a74ebd6746e13afe0eef5d66580c8e23d33464c342dc0080",
"039e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57",
"0322213b78f3dcfbdfeb76cc1731c1ba318b2b0c32f081e206f50618fa7eaf5aa3",
"03176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66",
"028758a9fd232f0fe9a7afc8456a40d57bc46e2a586d37641c2d6c77bcac938f93",
"0275d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8",
"0269b47c7249439d23a5f3c28db17e60da861a483939a113e2d903e0547bb26bfb",
"03809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721",
"035654834268843e72c300e97d5188fca2ed04459e09ca4351475a62c4bc8ade53",
"031b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180",
"038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508",
"0290a80db6eb294b9eab0b4e8ddfa3efe7263458ce2d07566df4e6c58868feef23",
"02545f13c023715040ea7d7701363c4285552b572eda6a27a20f458aaa1bbf1433",
"02c2c80f844b70599812d625460f60340e3e6f36054a14546e6dc25d47376bea9b",
"03f27cddeea945ef4047108936b531bb68957e1dc74ca938084632645c569f8346",
"039cf606744cf4b5f3fdf989d3f19fb2652d00cfe1d5fcd692a323ce11a28e7553",
"02b54d9afb4f81394d6604467edd323c314fb004d707db9cc0623833d9037c07df",
"0257488fa28742c6b25a493fd6060d936ea6280b0c742005abce98f5855ad82208",
"024a5f2b9f56c13dc77430ee6e589c05e56b71482e30faaf96c3af58d3e8e65bc6",
"03f1133cbe6be8bbc8dc8df2b8d75963c2d40ed616c758cdc84edbc5eb4899447d",
"03630aca4d7f4e5d9288f2f14b83fec5049c05377aaad025370951b67458ef54d7",
"0295083e753301bd787f8989c79065bb813f3d69bff3e425050f4e04175bbe89c0",
"0214e333e19222ffaf7a5a04b09d46f6f182d033abe15ee1a094cd2910186a92df",
"021a908355cbb756755e576ed29c99af638668c7b363c8d97362100443bc5c75c6",
"02d1e0265aa86ae428c75f9d4d45b2b643c8245d6ffb4bbc43bd6b7cea1ad3ec49",
"02c5922f740bd343d5aa867308fad97f9f8a2d1f63c5f31db4f04df3bef349b648",
"03a83d1893ba454e96c9c91effca154cde3ff705cf3d8eb91010758152439f943f",
"0264e1b1969f9102977691a40431b0b672055dcf31163897d996434420e6c95dc9",
"022290006b8d17b03cfe370eeb9075043ec818a14cee53f767d44a3a5d1fb1dfa8",
"03033b2e76687744ed6c521bad3333dd37c602f8a7549e9ce7808fb7ea07ce08de",
"020bbba8d764098dc402ca9a53d9d22580a5a4f8a80adcdb140225a6e483cf4b80",
"0220f18f4c866d8a1cc2a3103317b4ac3189fbf30ff294a75c951473be45e4f294",
"02aa336dda311186a2a8dfaa5328fffedffca6476eed1fd8d69fbf74b955b3edc6",
"024d1623c944c9c716a0eb4c685e2a8b9d2df3465354643befd1444176d7b69a8b",
"020f66dc33e335abc9a7c06f71ad2c0db65d5ac4b6f46d2dad9465e6a4ac04dc3f",
"03a901b0dbe8ab292d280d6b36858947854faad0a4dd0da7e2d4ad0ff53db079e0",
"03bb8a643d0f0c3991efdb401c11354c5e54f28fa8f3f367e3ef5f2776b40cbed5",
"037e0af07130218ffd50bd66f4484645b12f42a24f7c80889b3031c9a6ebfc9a70",
"02fe330b776c5f5c95b8eb0201cecc40e57353c30a84f9fde9fb37d7c0fa4753a8",
"037ba8187e1a7b25a2c185d335440a9038b47f0528546e9da4ef82aab05aebf20d",
"024b8b2d95c98777ba4663785ce387c4ac220c57cb0d48496c241dd1f60f2ce57b",
"028c050fc34d83b279b6000816e18fca389767b7960e92677255b84a39d93a6807",
"030b07d3e8dbbe686e5e1637258402cac30e1e4f29fdf154f7bf008c5f9969da10",
};


int SIZE_PK = 0x120 - 0x20;




const char *version = "v2.3";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};
//const char *op[2] = {"add","sub"};

void showhelp();
void set_format(char *param);
void set_look(char *param);
void set_bit(char *param);
void set_publickey(char *param);
void set_range(char *param);
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void generate_strrmd160(struct Point *publickey,bool compress,char *dst);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);
double_t calc_perc(uint64_t x, uint64_t max);

char *str_output = NULL;

char str_logout[140];


char str_publickey[131];
char str_rmd160[41];
char str_address[41];

struct Point target_publickey,base_publickey,sum_publickey,negated_publickey,dst_publickey;

int FLAG_RANGE = 0;
int FLAG_BIT = 0;
int FLAG_RANDOM = 0;
int FLAG_PUBLIC = 0;
int FLAG_FORMART = 0;
int FLAG_HIDECOMMENT = 0;
int FLAG_XPOINTONLY = 0;
int FLAG_LOOK = 0;
int FLAG_ADD = 0;
int FLAG_SUB = 0;
int FLAG_MODE = 0;
int FLAG_N;
uint64_t N = 0,M;

mpz_t min_range,max_range,diff,TWO,base_key,sum_key,dst_key;
gmp_randstate_t state;

void Point_Doubling(struct Point *P, struct Point *R)	{

   	//mp_snprintf(str_logout,131,"04%0.64Zx ; %0.64Zx",P->x,P->y);
	//fprintf(stderr,"\n Doubling P: %s \n",str_logout);

	mpz_t slope, temp;
	mpz_init(temp);
	mpz_init(slope);
	if(mpz_cmp_ui(P->y, 0) != 0) {
		mpz_mul_ui(temp, P->y, 2);
		mpz_invert(temp, temp, EC.p);
		mpz_mul(slope, P->x, P->x);
		mpz_mul_ui(slope, slope, 3);
		mpz_mul(slope, slope, temp);
		mpz_mod(slope, slope, EC.p);
		mpz_mul(R->x, slope, slope);
		mpz_sub(R->x, R->x, P->x);
		mpz_sub(R->x, R->x, P->x);
		mpz_mod(R->x, R->x, EC.p);
		mpz_sub(temp, P->x, R->x);
		mpz_mul(R->y, slope, temp);
		mpz_sub(R->y, R->y, P->y);
		mpz_mod(R->y, R->y, EC.p);
	} else {
		mpz_set_ui(R->x, 0);
		mpz_set_ui(R->y, 0);
	}
	mpz_clear(temp);
	mpz_clear(slope);

	//gmp_snprintf(str_logout,131,"04%0.64Zx ; %0.64Zx",R->x,R->y);
	//fprintf(stderr,"\nR: %s \n",str_logout);
}

void Point_Addition(struct Point *P, struct Point *Q, struct Point *R)	{
	mpz_t PA_temp,PA_slope;
	mpz_init(PA_temp);
	mpz_init(PA_slope);

	/*gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",P->x,P->y);
	fprintf(stderr,"\nP: %s \n",str_logout);

	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",Q->x,Q->y);
	fprintf(stderr,"Q: %s \n",str_logout);*/

	if(mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0) {
		mpz_set(R->x, Q->x);
		mpz_set(R->y, Q->y);
	}
	else	{
		if(mpz_cmp_ui(Q->x, 0) == 0 && mpz_cmp_ui(Q->y, 0) == 0) {
			mpz_set(R->x, P->x);
			mpz_set(R->y, P->y);
		}
		else	{
			if(mpz_cmp_ui(Q->y, 0) != 0) {
				mpz_sub(PA_temp, EC.p, Q->y);
				mpz_mod(PA_temp, PA_temp, EC.p);
			}
			else	{
				mpz_set_ui(PA_temp, 0);
			}
			if(mpz_cmp(P->y, PA_temp) == 0 && mpz_cmp(P->x, Q->x) == 0) {
				mpz_set_ui(R->x, 0);
				mpz_set_ui(R->y, 0);
			}
			else	{
				if(mpz_cmp(P->x, Q->x) == 0 && mpz_cmp(P->y, Q->y) == 0)	{
					Point_Doubling(P, R);
				}
				else {
					mpz_set_ui(PA_slope, 0);
					mpz_sub(PA_temp, P->x, Q->x);	//dx = B.x - A.x
					mpz_mod(PA_temp, PA_temp, EC.p);		///dx = dx % p
					mpz_invert(PA_temp, PA_temp, EC.p);	//gmpy2.invert(dx, p) % p
					mpz_sub(PA_slope, P->y, Q->y);
					mpz_mul(PA_slope, PA_slope, PA_temp);
					mpz_mod(PA_slope, PA_slope, EC.p);
					mpz_mul(R->x, PA_slope, PA_slope);	//c*c
					mpz_sub(R->x, R->x, P->x);	//	c*c - A.x
					mpz_sub(R->x, R->x, Q->x);	//(c*c - A.x) -	B.x
					mpz_mod(R->x, R->x, EC.p);	// Rx % p
					mpz_sub(PA_temp, P->x, R->x);
					mpz_mul(R->y, PA_slope, PA_temp);
					mpz_sub(R->y, R->y, P->y);
					mpz_mod(R->y, R->y, EC.p);
				}
			}
		}
	}
	mpz_clear(PA_temp);
	mpz_clear(PA_slope);

    //gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",R->x,R->y);
	//fprintf(stderr,"R: %s \n\n",str_logout);

}

void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m)	{
	struct Point SM_T,SM_Q;
	int no_of_bits, i;
	no_of_bits = mpz_sizeinbase(m, 2);
	mpz_init_set_ui(SM_Q.x,0);
	mpz_init_set_ui(SM_Q.y,0);
	mpz_init_set_ui(SM_T.x,0);
	mpz_init_set_ui(SM_T.y,0);
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	if(mpz_cmp_ui(m, 0) != 0)	{
		mpz_set(SM_Q.x, P.x);
		mpz_set(SM_Q.y, P.y);
		for(i = 0; i < no_of_bits; i++) {
			if(mpz_tstbit(m, i))	{
				mpz_set(SM_T.x, R->x);
				mpz_set(SM_T.y, R->y);
				mpz_set(SM_Q.x,DoublingG[i].x);
				mpz_set(SM_Q.y,DoublingG[i].y);
				Point_Addition(&SM_T, &SM_Q, R);
			}
		}
	}
	mpz_clear(SM_T.x);
	mpz_clear(SM_T.y);
	mpz_clear(SM_Q.x);
	mpz_clear(SM_Q.y);
}

void Point_Negation(struct Point *A, struct Point *S)	{
    gmp_snprintf(str_logout,135,"04%0.64Zx ;%0.64Zx",A->x,A->y);
	fprintf(stderr,"Negation A: %s \n",str_logout);

	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",S->x,S->y);
	fprintf(stderr,"Negation S: %s \n",str_logout);

	mpz_sub(S->y, EC.p, A->y);
	mpz_set(S->x, A->x);

	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",A->x,A->y);
	fprintf(stderr,"Neg Res A: %s \n",str_logout);

	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",S->x,S->y);
	fprintf(stderr,"Neg Res S: %s \n\n",str_logout);
}

// return 0 if A>B else 1
int Compare_Points(struct Point *A, struct Point *B){

    struct Point C, D;
    fprintf(stderr,"\n\n\nCompare\n");

    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",A->x,A->y);
	fprintf(stderr,"A: %s \n\n",str_logout);
	gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",B->x,B->y);
	fprintf(stderr,"B: %s \n\n",str_logout);

    int res_cmp = mpz_tstbit(A->y,0);
    mpz_init(C.x);
	mpz_init(C.y);
	mpz_init(D.x);
	mpz_init(D.y);


    Point_Negation(B,&C);
    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",C.x,C.y);
	fprintf(stderr,"Negate: %s \n\n",str_logout);
    Point_Addition(A,&C,&D);
    gmp_snprintf(str_logout,135,"04%0.64Zx ; %0.64Zx",D.x,D.y);
	fprintf(stderr,"Subtra: %s \n\n",str_logout);
    fprintf(stderr,"A.y=%d ",res_cmp);
    res_cmp ^= mpz_tstbit(D.y,0);
    mpz_clear(C.x);
	mpz_clear(C.y);
	mpz_clear(D.x);
	mpz_clear(D.y);
    fprintf(stderr,"D=%d\n",mpz_tstbit(D.y,0));
    return res_cmp;
}


//-1 if pub_key is not present in array,
// index>0 - index of pub_key in array
int look_up_pk(char* pub_key, char range_pk[][67], int size_array){

    int i = 0;
    int j = size_array-1;
    int res = -1;
    for(;i<=j;i++,j--){
        /*mpz_t value;
        mpz_init(value);
        mpz_init_set_str(value,range_pk[i],16);*/
        if(strcmp(range_pk[i],pub_key)==0){
            res = i;
            //mpz_clear(value);
            return i;
        }
        //mpz_t value2;
        //mpz_init(value2);
        //mpz_init_set_str(range_pk[j],(char*)range_pk[j],16);
        if(strcmp(range_pk[j],pub_key)==0){
            res = j;
            //mpz_clear(value2);
            return j;
        }
    }

    return res;
}

/*
	Precalculate G Doublings for Scalar_Multiplication
*/
void init_doublingG(struct Point *P)	{
	int i = 0;
	mpz_init(DoublingG[i].x);
	mpz_init(DoublingG[i].y);
	mpz_set(DoublingG[i].x,P->x);
	mpz_set(DoublingG[i].y,P->y);
	i = 1;
	while(i < 256){
		mpz_init(DoublingG[i].x);
		mpz_init(DoublingG[i].y);
		Point_Doubling(&DoublingG[i-1] ,&DoublingG[i]);
		mpz_mod(DoublingG[i].x, DoublingG[i].x, EC.p);
		mpz_mod(DoublingG[i].y, DoublingG[i].y, EC.p);
		i++;
	}
}

int main(int argc, char **argv)  {
	FILE *OUTPUT;
	char c;
	uint64_t i = 0;
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);

	mpz_init(min_range);
	mpz_init(max_range);
	mpz_init(diff);
	mpz_init_set_ui(TWO,2);
	mpz_init(target_publickey.x);
	mpz_init_set_ui(target_publickey.y,0);


	struct Point INTERVAL_FIRST;
	struct Point INTERVAL_LAST;
    mpz_t TEMP1,TEMP2;
	mpz_init(TEMP1);

	mpz_init(INTERVAL_FIRST.x);
    mpz_init(INTERVAL_FIRST.y);
    mpz_init(INTERVAL_LAST.x);
    mpz_init(INTERVAL_LAST.y);

	mpz_init_set_str(TEMP1, MIN_DOM, 16);
	gmp_fprintf(stderr, "Temp %0.64Zx\n", TEMP1);

	Scalar_Multiplication(G,&INTERVAL_FIRST, TEMP1);
	gmp_fprintf(stderr, "X %0.64Zx\n", INTERVAL_FIRST.x);
    gmp_fprintf(stderr, "Y %0.64Zx\n", INTERVAL_FIRST.y);

	mpz_clear(TEMP1);
	mpz_init(TEMP2);

	mpz_init_set_str(TEMP2, MAX_DOM, 16);

	Scalar_Multiplication(G,&INTERVAL_LAST, TEMP2);
    mpz_clear(TEMP2);
    gmp_fprintf(stderr, "X %0.64Zx\n", INTERVAL_LAST.x);
    gmp_fprintf(stderr, "Y %0.64Zx\n", INTERVAL_LAST.y);


	while ((c = getopt(argc, argv, "hvaszxRb:n:o:p:r:f:l:")) != -1) {


		switch(c) {
			case 'x':
				FLAG_HIDECOMMENT = 1;
			break;
			case 'z':
				FLAG_XPOINTONLY = 1;
			break;
			case 'a':
				FLAG_ADD = 1;
			break;
			case 's':
				FLAG_SUB = 1;
			break;
			case 'h':
				showhelp();
				exit(0);
			break;
			case 'b':
				set_bit((char *)optarg);
				FLAG_BIT = 1;
			break;
			case 'n':
				N = strtol((char *)optarg,NULL,10);
				if(N<= 0)	{
					fprintf(stderr,"[E] invalid bit N number %s\n",optarg);
					exit(0);
				}
				FLAG_N = 1;
			break;
			case 'o':
				str_output = (char *)optarg;
			break;
			case 'p':
				set_publickey((char *)optarg);
				FLAG_PUBLIC = 1;
			break;
			case 'r':
				set_range((char *)optarg);
				FLAG_RANGE = 1;
			break;
			case 'R':
				FLAG_RANDOM = 1;
			break;
			case 'v':
				printf("Version %s\n",version);
				exit(0);
			break;
			case 'l':
				set_look((char *)optarg);
			break;

			case 'f':
				set_format((char *)optarg);
			break;

		}
	}

#ifdef DEBUG
	for(int j=0;j<argc;j++){
            fprintf(stderr,"%s ", argv[j]);
        }
        fprintf(stderr, "%d, %d, %d,%d\n\n\n", FLAG_BIT, FLAG_RANGE, FLAG_PUBLIC, FLAG_N);
#endif

    fprintf(stderr,"\n start working\n");

	if((FLAG_BIT || FLAG_RANGE) && FLAG_PUBLIC && FLAG_N)	{
		if(str_output)	{
			OUTPUT = fopen(str_output,"a");
			if(OUTPUT == NULL)	{
				fprintf(stderr,"can't opent file %s\n",str_output);
				OUTPUT = stdout;
			}
		}
		else	{
			OUTPUT = stdout;
		}
		if(N % 2 == 1)	{
			N++;
		}
		//M = N /2;
		if(FLAG_SUB && FLAG_ADD) {
			M = N / 2;
		}
		else if(FLAG_ADD) {
			M = N;
		}
		else if(FLAG_SUB) {
			M = N;
		}
		else {
			M = N /2;
		}

		mpz_sub(diff,max_range,min_range);
		mpz_init(base_publickey.x);
		mpz_init(base_publickey.y);
		mpz_init(sum_publickey.x);
		mpz_init(sum_publickey.y);
		mpz_init(negated_publickey.x);
		mpz_init(negated_publickey.y);
		mpz_init(dst_publickey.x);
		mpz_init(dst_publickey.y);
		mpz_init(base_key);
		mpz_init(sum_key);

		fprintf(stderr,"\n inited %d\n", FLAG_RANDOM);

		if(FLAG_RANDOM)	{
			gmp_randinit_mt(state);
			gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)) );
			for(i = 0; i < M;i++)	{
				mpz_urandomm(base_key,state,diff);
				Scalar_Multiplication(G,&base_publickey,base_key);
				Point_Negation(&base_publickey,&negated_publickey);
				Point_Addition(&base_publickey,&target_publickey,&dst_publickey);

				switch(FLAG_FORMART)	{
					case 0: //Publickey
					if(FLAG_ADD) {
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # - %Zx\n", dst_publickey.x, base_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_publickey, base_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # + %Zx\n", dst_publickey.x, base_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_publickey, base_key);
						}
						}
					break;
					case 1: //rmd160
					if(FLAG_ADD) {
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_rmd160,base_key);

							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_rmd160, base_key);
						}

					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_rmd160,base_key);
							if(1000<i && i<10000){
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_rmd160, base_key);
						}
						}
						}
					break;
					case 2:	//address
					if(FLAG_ADD) {
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_address,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_address, base_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_address,base_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_address, base_key);
						}
						}
					break;
				}
				if (i % 10000 == 0) {
                    double_t perc = calc_perc(i, M);
                    printf("\r[+] Percent Complete: %0.2lf", perc);
                    fflush(stdout);
                }
			}

			switch(FLAG_FORMART)	{
				case 0: //Publickey

					generate_strpublickey(&target_publickey,FLAG_LOOK == 0,str_publickey);
					if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", target_publickey.x);
						}
					else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # target\n", target_publickey.x);
						}
					else if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_publickey);
					}

					else	{
						fprintf(OUTPUT,"%s # target\n",str_publickey);
					}
				break;
				case 1: //rmd160
					generate_strrmd160(&target_publickey,FLAG_LOOK == 0,str_rmd160);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_rmd160);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_rmd160);
					}
				break;
				case 2:	//address
					generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_address);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_address);
					}
				break;
			}
			if (i = M) {// ???
                    double_t perc = calc_perc(i, M);
                    //printf("\r[+] Percent Complete: %0.6lf", perc);
					printf("\r[+] Percent Complete: Finished");
                    fflush(stdout);
                }
		}
		else	{
                fprintf(stderr,"NOn random %d Format %d",M, FLAG_FORMART);
			mpz_cdiv_q_ui(base_key,diff,M);
			//mpz_cdiv_q_ui(base_key,min_range,1);

			Scalar_Multiplication(G,&base_publickey,base_key);
			mpz_set(sum_publickey.x,base_publickey.x);
			mpz_set(sum_publickey.y,base_publickey.y);
			mpz_set(sum_key,base_key);
			fprintf(stderr,"scalar mult done\n");

			gmp_snprintf(str_logout,135,"04%0.64Zx ;%0.64Zx",base_publickey.x,base_publickey.y);
			fprintf(stderr,"Public Key: %s \n",str_logout);

			for(i = 0; i < M;i++)	{
                fprintf(stderr,"iter %d %d, negation:\n",i,FLAG_ADD);
				Point_Negation(&sum_publickey,&negated_publickey);
				fprintf(stderr,"add \n");
				Point_Addition(&sum_publickey,&target_publickey,&dst_publickey);
                gmp_fprintf(stderr, "%Zd %d\n", base_key,i);
       			//gmp_snprintf(str_logout,135,"04%0.64Zx ;%0.64Zx",base_publickey.x,base_publickey.y);
                //gmp_fprintf(OUTPUT, "!!!!!!!!!!!!LOG: %0.64Zx\n", str_logout);



				if (0){
                      int r1 = Compare_Points(&dst_publickey,&INTERVAL_FIRST);
                      fprintf(stderr,"r1 = %d\n",r1);
                      int r2 = Compare_Points(&dst_publickey,&INTERVAL_LAST);
                      fprintf(stderr,"r2 = %d\n",r2);

                      if((!r1) && (r2)){
                          fprintf(stderr,"Inside interval\n");

                          //mpz_set(dst_publickey.x,base_publickey.x);
                          //mpz_set(dst_publickey.y,base_publickey.y);
                      }

				}





				switch(FLAG_FORMART)	{
					case 0: //Publickey
						if(FLAG_ADD) {
                             fprintf(stderr,"generation:\n ");

						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						     fprintf(stderr,"out:\n ");
						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # - %Zx\n", dst_publickey.x, sum_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_publickey, sum_key);
						}
						}

						if(FLAG_SUB) {
                                 fprintf(stderr,"addition, generation:\n ");
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
					     fprintf(stderr,"out:\n ");


                       gmp_fprintf(OUTPUT, "!!!!!!!!!!!%s # - %Zx\n", str_publickey, sum_key);
                       gmp_fprintf(stderr, "D=%0.64Zx , %0.64Zx\n", dst_publickey.x, dst_publickey.y);
                       str_publickey[66]='\0';
						int looked_up_val  = look_up_pk(str_publickey, RANGE_PK, SIZE_PK);

				        if (looked_up_val>0){
                    fprintf(stderr,"Inside interval\n");
                    //generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
					fprintf(stderr,"out:\n ");
                    gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
                    //break;
				     }

						if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", dst_publickey.x);
						}
						else if(FLAG_XPOINTONLY)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # + %Zx\n", dst_publickey.x, sum_key);
						}
						else if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
							gmp_fprintf(OUTPUT, "%s # A- %Zx\n", str_publickey, sum_key);
						}
						}

					break;
					case 1: //rmd160
					if(FLAG_ADD) {
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_rmd160,sum_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_rmd160, sum_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_rmd160,sum_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_rmd160, sum_key);
						}
						}
					break;
					case 2:	//address
					if(FLAG_ADD) {
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_address,sum_key);
							gmp_fprintf(OUTPUT, "%s # - %Zx\n", str_address, sum_key);
						}
					}
						if(FLAG_SUB) {
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}

						else	{
							//gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_address,sum_key);
							gmp_fprintf(OUTPUT, "%s # + %Zx\n", str_address, sum_key);
						}
						}
					break;
				}

				fprintf(stderr,"Final add:\n ");
				Point_Addition(&sum_publickey,&base_publickey,&dst_publickey);
				mpz_set(sum_publickey.x,dst_publickey.x);
				mpz_set(sum_publickey.y,dst_publickey.y);
				mpz_add(sum_key,sum_key,base_key);
				if (i % 10000 == 0) {
                    double_t perc = calc_perc(i, M);
                    printf("\r[+] Percent Complete: %0.2lf", perc);
                    fflush(stdout);
                }
			}

			fprintf(stderr,"Final Output:\n ");
			switch(FLAG_FORMART)	{
				case 0: //Publickey
					generate_strpublickey(&target_publickey,FLAG_LOOK == 0,str_publickey);
					if(FLAG_HIDECOMMENT && FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx\n", target_publickey.x);
						}
					else if(FLAG_XPOINTONLY)	{
							//fprintf(OUTPUT,"%s\n",str_publickey);
							gmp_fprintf(OUTPUT, "%0.64Zx # target\n", target_publickey.x);
						}
					else if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_publickey);
					}

					else	{
						fprintf(OUTPUT,"%s # target\n",str_publickey);
					}
				break;
				case 1: //rmd160
					generate_strrmd160(&target_publickey,FLAG_LOOK == 0,str_rmd160);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_rmd160);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_rmd160);
					}
				break;
				case 2:	//address
					generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_address);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_address);
					}
				break;
			}
			if (i == M) {
                    double_t perc = calc_perc(i, M);
                    //printf("\r[+] Percent Complete: %0.6lf", perc);
					printf("\r[+] Percent Complete: Finished");
                    fflush(stdout);
                }
		}

		mpz_clear(base_publickey.x);
		mpz_clear(base_publickey.y);
		mpz_clear(sum_publickey.x);
		mpz_clear(sum_publickey.y);
		mpz_clear(negated_publickey.x);
		mpz_clear(negated_publickey.y);
		mpz_clear(dst_publickey.x);
		mpz_clear(dst_publickey.y);
		mpz_clear(base_key);
		mpz_clear(sum_key);
	}
	else	{
#ifdef DEBUG
        for(int j=0;j<argc;j++){
            fprintf(stderr,"%s ", argv[j]);
        }
        fprintf(stderr, "%d, %d, %d,%d", FLAG_BIT, FLAG_RANGE, FLAG_PUBLIC, FLAG_N);
#endif
		fprintf(stderr,"\nVersion: %s\n",version);
		fprintf(stderr,"[E] There are some missing parameter(s)\n");
		showhelp();
	}
	return 0;
}

void showhelp()	{
	printf("\nUsage:\n-h\t\tShow this help screen.\n");
	printf("-b bits\t\tFor subtracting and addition enter a bit range.\n");
	printf("-f format\tOutput format <publickey, rmd160, address>. Default: publickey\n");
	printf("-l look\t\tOutput <compressed, uncompressed>. Default: compress\n");
	printf("-n number\tNumber of public keys to generate. This number needs to be even.\n");
	printf("-o file\t\tOutput file. If you omit this option, results will be printed on screen.\n");
	printf("-p key\t\tPublickey to be added/subtracted; can be compressed or uncompressed.\n");
	printf("-r A:B\t\tRange A to B; ex: -r 2000000000:3000000000\n");
	printf("-R\t\tRandom addition/subtraction publickey instead of sequential.\n");
	printf("-a\t\tAddition only to the public key.\n");
	printf("-s\t\tSubtraction only to the public key.\n");
	printf("NOTE:\n\t\tIf you want to add and subtract from public key, use the -s and -a flags at the same time.\n\n");
	printf("-z\t\tX Point only. It will exclude the even (02) and odd (03) parity of the Y coord.\n");
	printf("-x\t\tExclude comments; the + and/or - columns. You need the comments if using Random mode.\n");
	printf("NOTE:\n\t\tThe + or - comments are telling you what to add or subtract from found key.\n\t\tIf you use -s, subtraction only, you need to add + the number to found key,\n\t\tto equal the actual key you are looking for.\n\n");
	printf("Property of SSD pvt\n\n");
}

void set_bit(char *param)	{
	mpz_t MPZAUX;
	int bitrange = strtol(param,NULL,10);
	if(bitrange > 0 && bitrange <=256 )	{
		mpz_init(MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange-1);
		mpz_set(min_range,MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange);
		mpz_sub_ui(MPZAUX,MPZAUX,1);
		mpz_set(max_range,MPZAUX);
		printf("[+] KeySubtractor\n");
		printf("[+] Version %s\n",version);
		fprintf(stderr, "[+] Keys to Generate: %d\n", N);
		gmp_fprintf(stderr,"[+] Min range: %Zx\n",min_range);
		gmp_fprintf(stderr,"[+] Max range: %Zx\n",max_range);
		mpz_clear(MPZAUX);
	}
	else	{
		fprintf(stderr,"[E] Invalid bit paramaters: %s\n",param);
		exit(0);
	}
}

void set_publickey(char *param)	{
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue,0,65);
	memcpy(dest,param,len);
	trim(dest," \t\n\r");
	len = strlen(dest);
	switch(len)	{
		case 66:
			mpz_set_str(target_publickey.x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(target_publickey.x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(target_publickey.y,hexvalue,16);
		break;
	}
	if(mpz_cmp_ui(target_publickey.y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,target_publickey.x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(target_publickey.y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,target_publickey.y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(target_publickey.y, 0) == 1)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(target_publickey.y, 0) == 0)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			default:
				fprintf(stderr,"[E] Some invalid bit in the publickey: %s\n",dest);
				exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}

void set_range(char *param)	{
	Tokenizer tk;
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memcpy(dest,param,len);
	dest[len] = '\0';
	stringtokenizer(dest,&tk);
	if(tk.n == 2)	{
		mpz_init_set_str(min_range,nextToken(&tk),16);
		mpz_init_set_str(max_range,nextToken(&tk),16);
		printf("[+] Version %s\n",version);
		printf("[+] KeySubtractor\n");
		fprintf(stderr, "[+] Keys to Generate: %d\n", N);
		gmp_fprintf(stderr, "[+] Min range: %Zx\n", min_range);
        gmp_fprintf(stderr, "[+] Max range: %Zx\n", max_range);
	}
	else	{
		fprintf(stderr,"%i\n",tk.n);
		fprintf(stderr,"[E] Invalid range. Expected format A:B\n");
		exit(0);
	}
	freetokenizer(&tk);
	free(dest);
}

double_t calc_perc(uint64_t x, uint64_t max)
{
    return (double_t)(((double_t)x) / ((double_t)max) * 100.0 /*+ 0.5*/);
}

void set_format(char *param)	{
	int index = indexOf(param,formats,3);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknown format: %s\n",param);
	}
	else	{
		FLAG_FORMART = index;
	}
}

void set_look(char *param)	{
	int index = indexOf(param,looks,2);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknown look: %s\n",param);
	}
	else	{
		FLAG_LOOK = index;
	}
}




void generate_strpublickey(struct Point *publickey,bool compress,char *dst)	{
	memset(dst,0,132);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst,67,"03%0.64Zx",publickey->x);
		}
	}
	else	{
		gmp_snprintf(dst,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
	}
}

void generate_strrmd160(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_rmd160[20];
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_rmd160);
	tohex_dst(bin_rmd160,20,dst);
}

void generate_straddress(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 42;
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);

	/* Firts byte 0, this is for the Address begining with 1.... */

	bin_digest[0] = 0;

	/* Double sha256 checksum */
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);

	/* Get the address */
	if(!b58enc(dst,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}
