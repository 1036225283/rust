use bitcoin_wallet::account::{Account, AccountAddressType, MasterAccount, Unlocker};
use bitcoin_wallet::bitcoin::blockdata::script::Script;
use bitcoin_wallet::bitcoin::blockdata::transaction::{
    OutPoint, SigHashType, Transaction, TxIn, TxOut,
};
use bitcoin_wallet::bitcoin::blockdata::{opcodes, script};
use bitcoin_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin_wallet::bitcoin::hashes::hex::FromHex;
use bitcoin_wallet::bitcoin::network::constants::Network;
use bitcoin_wallet::mnemonic::Mnemonic;
use hex;
use ocl::builders::ContextProperties;
use ocl::enums::ArgVal;
use ocl::prm::cl_ulong;
use ocl::{core, flags};
use rayon::prelude::*;
use reqwest;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::ops::Index;
use std::ptr::null;
use std::str;

const PASSPHRASE: &str = "";
const WORK_SERVER_URL: &str = "http://localhost:3000";
const WORK_SERVER_SECRET: &str = "secret";
const INPUT_TRANSACTION: &str = "0200000002b927da7d93d6168ada9d471aa4bea50c70323353aae68b39faa08ffc7ae15265010000006a473044022035dc74cb164947397d639ae6e5b148fa2b1f1d6a93239555b4b058425c6328b002206e90486b11da907e35a14b454b17bead964e1507821a99d7fe960d1643d13294012103786af4b32017ec640dba2d2a7e1fd5aa4a231a658e4cbc114d51c031576e19bcffffffff665a5990fd90f1e6457a0704da5a067a6caca6dd91e3e921869ce884bb4af8a6020000006a473044022022dfe92099a3f896ff84fdab6bd1d99c2c8a17d9ecaedd26f093cf444382e7220220118f77d80a36525c1d95f0bd990baa7ffbcf499ccf4f8289b39c2d4ee77e1068012103786af4b32017ec640dba2d2a7e1fd5aa4a231a658e4cbc114d51c031576e19bcffffffff0300e1f5050000000017a914ada12b113d9b19614757d19fc08ddd534bf0227687ea4b04000000000017a9140997ff827d755a356d7ddb83a789b5954611c9c78758f8f698080000001976a914cebb2851a9c7cfe2582c12ecaf7f3ff4383d1dc088ac00000000";

#[derive(Deserialize, Debug)]
struct WorkResponse {
    indices: Vec<u128>,
    offset: u128,
    batch_size: u64,
}

struct WorkResponse2 {
    arr: Vec<u64>,
}
struct Work {
    start_hi: u64,
    start_lo: u64,
    batch_size: u64,
    offset: u128,
}

struct Work2 {
    arr: Vec<u64>,
}

fn sweep_btc(mnemonic: String) {
    let tx_bytes: Vec<u8> = Vec::from_hex(INPUT_TRANSACTION).unwrap();
    let input_transaction: Transaction = deserialize(&tx_bytes).unwrap();

    let mnemonic = Mnemonic::from_str(&mnemonic).unwrap();
    let mut master =
        MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();
    let mut unlocker = Unlocker::new_for_master(&master, PASSPHRASE).unwrap();
    let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
    master.add_account(account);

    // this is the raw address of where to send the coins
    let target_address_bytes = [];
    let amount_to_spend = 99000000;

    let script_pubkey = script::Builder::new()
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&target_address_bytes)
        .push_opcode(opcodes::all::OP_EQUAL)
        .into_script();

    let txid = input_transaction.txid();
    const RBF: u32 = 0xffffffff - 2;

    let mut spending_transaction = Transaction {
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            sequence: RBF,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: script_pubkey,
            value: amount_to_spend,
        }],
        lock_time: 0,
        version: 2,
    };

    master
        .sign(
            &mut spending_transaction,
            SigHashType::All,
            &(|_| Some(input_transaction.output[0].clone())),
            &mut unlocker,
        )
        .expect("can not sign");
    let rawtx = hex::encode(serialize(&spending_transaction));
    broadcast_tx(rawtx);
}

fn broadcast_tx(rawtx: String) {
    let mut json_body = HashMap::new();
    json_body.insert("tx", rawtx);
    let client = reqwest::blocking::Client::new();
    let _res = client
        .post("https://api.blockcypher.com/v1/btc/main/txs/push")
        .json(&json_body)
        .send();
}

fn log_solution(offset: u128, mnemonic: String) {
    let mut json_body = HashMap::new();
    json_body.insert("mnemonic", mnemonic);
    json_body.insert("offset", offset.to_string());
    json_body.insert("secret", WORK_SERVER_SECRET.to_string());
    let client = reqwest::blocking::Client::new();
    let _res = client
        .post(&format!("{}/mnemonic", WORK_SERVER_URL.to_string()).to_string())
        .json(&json_body)
        .send();
}

fn log_work(offset: u128) {
    let mut json_body = HashMap::new();
    json_body.insert("offset", offset.to_string());
    json_body.insert("secret", WORK_SERVER_SECRET.to_string());
    let client = reqwest::blocking::Client::new();
    let _res = client
        .post(&format!("{}/work", WORK_SERVER_URL.to_string()).to_string())
        .json(&json_body)
        .send();
}

fn get_work() -> Work {
    let response = reqwest::blocking::get(
        &format!(
            "{}/work?secret={}",
            WORK_SERVER_URL.to_string(),
            WORK_SERVER_SECRET.to_string()
        )
        .to_string(),
    )
    .unwrap();

    let work_response: WorkResponse = response.json().unwrap();

    let mut start: u128 = 0;
    let mut start_shift = 128;

    for idx in &work_response.indices {
        start_shift -= 11;
        start = start | (idx << start_shift);
    }

    start += work_response.offset;
    let start_lo: u64 = ((start << 64) >> 64) as u64;
    let start_hi: u64 = (start >> 64) as u64;

    return Work {
        start_lo: start_lo,
        start_hi: start_hi,
        batch_size: work_response.batch_size,
        offset: work_response.offset,
    };
}

fn get_entity() -> Work {
    let response = reqwest::blocking::get(
        &format!(
            "{}/hello?secret={}",
            WORK_SERVER_URL.to_string(),
            WORK_SERVER_SECRET.to_string()
        )
        .to_string(),
    )
    .unwrap();
    let work_response: WorkResponse = response.json().unwrap();

    let mut start: u128 = 0;
    let mut start_shift = 128;

    for idx in &work_response.indices {
        start_shift -= 11;
        start = start | (idx << start_shift);
    }

    start += work_response.offset;
    let start_lo: u64 = ((start << 64) >> 64) as u64;
    let start_hi: u64 = (start >> 64) as u64;

    return Work {
        start_lo: start_lo,
        start_hi: start_hi,
        batch_size: work_response.batch_size,
        offset: work_response.offset,
    };
}

static data_size: i32 = 500000 * 32;

fn mnemonic_gpu(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: std::ffi::CString,
    kernel_name: &String,
) -> ocl::core::Result<()> {
    let context_properties = ContextProperties::new().platform(platform_id);
    let context =
        core::create_context(Some(&context_properties), &[device_id], None, None).unwrap();
    let program = core::create_program_with_source(&context, &[src]).unwrap();
    core::build_program(
        &program,
        Some(&[device_id]),
        &CString::new("").unwrap(),
        None,
        None,
    )
    .unwrap();
    let queue = core::create_command_queue(&context, &device_id, None).unwrap();

    loop {
        // let work: Work = get_work();
        let now = std::time::SystemTime::now();

        let work: Work = Work {
            start_lo: 16422911504526868480,
            start_hi: 867472538511601921,
            batch_size: 16777216,
            offset: 1157627904,
        };

        let flag = 2;
        if flag > 1 {
            println!("RUST flag > 1");
        }

        println!(
            "RUST start_hi = {},start_lo = {},batch_size = {},offset = {}",
            work.start_hi, work.start_lo, work.batch_size, work.offset
        );

        // let items: u64 = work.batch_size;
        let items: u64 = 500000;
        // let items: u64 = 1000;

        // let mnemonic_hi: cl_ulong = work.start_hi;
        let input_entropy_size: cl_ulong = 500000;

        let mut out_mnemonic = vec![0u8; 256];
        // let mut target_mnemonic = "banana high chronic sphere train medal evil ten good strike frequent daring then tower senior poverty face crack purpose appear quit shield palm boost".as_bytes().to_vec();
        // let mut target_mnemonic = "rhythm bulk shoulder shy mix finger fog artefact update obtain fresh clown tent inspire answer unaware teach action two captain street mammal rather fossil".as_bytes().to_vec();
        let input_entropy = create_entropy();
        // hex::decode("6becf1663a53eb3cbbf28a86a7e22fb91903fbd4fb7dbc54b81041929d070457")
        // .expect("msg");
        let mut mnemonic_found = vec![0u8; 1];

        let address = create_address();

        let mnemonic_hi: cl_ulong = input_entropy.len() as u64;

        let input_entropy_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                500000 * 32,
                Some(&input_entropy),
            )?
        };

        let out_mnemonic_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                256,
                Some(&out_mnemonic),
            )?
        };

        let input_address_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                20,
                Some(&address),
            )?
        };

        let kernel = core::create_kernel(&program, kernel_name)?;

        /**
        __kernel void int_to_address(ulong input_size, __global uchar *input_entropy,
                             __global uchar *target_mnemonic,
                             __global uchar *target_address) {
        */
        core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&input_entropy_size))?;
        core::set_kernel_arg(&kernel, 1, ArgVal::mem(&input_entropy_buf))?;
        core::set_kernel_arg(&kernel, 2, ArgVal::mem(&input_address_buf))?;
        core::set_kernel_arg(&kernel, 3, ArgVal::mem(&out_mnemonic_buf))?;

        unsafe {
            core::enqueue_kernel(
                &queue,
                &kernel,
                1,
                None,
                &[items as usize, 1, 1],
                None,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        unsafe {
            core::enqueue_read_buffer(
                &queue,
                &out_mnemonic_buf,
                true,
                0,
                &mut out_mnemonic,
                None::<core::Event>,
                None::<&mut core::Event>,
            )?;
        }

        // unsafe {
        //     core::enqueue_read_buffer(
        //         &queue,
        //         &mnemonic_found_buf,
        //         true,
        //         0,
        //         &mut mnemonic_found,
        //         None::<core::Event>,
        //         None::<&mut core::Event>,
        //     )?;
        // }

        // log_work(work.offset);

        if out_mnemonic[0] != 0 {
            let s = match String::from_utf8((&out_mnemonic[0..256]).to_vec()) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            println!(
                "RUST SUCCESS !!! the out mnemonic = {}",
                String::from_utf8(out_mnemonic).expect("msg")
            );
        }

        println!("RUST use time {:?}, ", now.elapsed().expect(""));

        println!("RUST this is end ");

        assert!(flag < 1);
        println!("RUST this assert ");
    }
}

fn main() {
    let platform_id = core::default_platform().unwrap();
    let device_ids =
        core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None).unwrap();

    let int_to_address_kernel: String = "int_to_address".to_string();
    let int_to_address_files = [
        "common",
        "ripemd",
        "sha2",
        "secp256k1_common",
        "secp256k1_scalar",
        "secp256k1_field",
        "secp256k1_group",
        "secp256k1_prec",
        "secp256k1",
        "address",
        "mnemonic_constants",
        "keccak_tiny",
        "int_to_address",
    ];

    // these were for testing performance of just calculating seed
    let _just_seed_kernel: String = "just_seed".to_string();
    let _just_seed_files = ["common", "sha2", "mnemonic_constants", "just_seed"];

    // these were for testing performance of just calculating address from a seed
    let _just_address_kernel: String = "just_address".to_string();
    let _just_address_files = [
        "common",
        "ripemd",
        "sha2",
        "secp256k1_common",
        "secp256k1_scalar",
        "secp256k1_field",
        "secp256k1_group",
        "secp256k1_prec",
        "secp256k1",
        "address",
        "just_address",
    ];

    let files = int_to_address_files;
    let kernel_name = int_to_address_kernel;

    let mut raw_cl_file = "".to_string();

    for file in &files {
        let file_path = format!("./cl/{}.cl", file);
        let file_str = fs::read_to_string(file_path).unwrap();
        raw_cl_file.push_str(&file_str);
        raw_cl_file.push_str("\n");
    }

    let src_cstring = CString::new(raw_cl_file).unwrap();

    // just_seed::test();

    // let work: Work = get_entity();

    // test();

    device_ids.into_par_iter().for_each(move |device_id| {
        mnemonic_gpu(platform_id, device_id, src_cstring.clone(), &kernel_name).unwrap()
    });
    // test_time();
    // test_bit();
}

// 根据助记词生成向量
// 根据向量生成助记词
fn test() {
    let s1 = String::from("hello");
    let s2 = &s1;
    println!("hello = {}", words[1]);
    show(&s1);
    println!("hello = {}", s1);
}

fn show(str: &String) {
    println!("show = {}", str)
}

fn test_create_entropy() {
    let b2: Vec<u8> = create_entropy();

    let mut i = 0;
    while i < 32 {
        println!("y = {:x}", b2[b2.len() - 32 + i]);
        i = i + 1;
    }
}

// 创建500000个32位数组
fn create_entropy() -> Vec<u8> {
    let mut b2: Vec<u8> = Vec::new();
    // 填充entropy
    let input_entropy =
        hex::decode("6becf1663a53eb3cbbf28a86a7e22fb91903fbd4fb7dbc54b81041929d070457")
            .expect("msg");
    let mut i = 0;
    while i < 500000 {
        let mut j = 0;
        while j < 32 {
            b2.push(input_entropy[j]);
            j = j + 1;
        }
        i = i + 1;
    }

    let test_entropy =
        hex::decode("8a5ac968ea198138f26d68099028d4417da0d30deb4030a0a32eaf7a41991523")
            .expect("msg");

    // 倒数第二个
    let len = b2.len();
    let mut i = 0;
    while i < 32 {
        b2[len - 32 + i] = test_entropy[i];
        i = i + 1;
    }
    // println!("the last = {}", b2[b2.len() - 1]);
    b2.to_vec()
}

// 创建20字节的地址数组
fn create_address() -> Vec<u8> {
    let address = hex::decode("7127e93651CC9d3AD3c0e5499Dba43cB765783E2").expect("msg");
    address
}

fn five() -> i32 {
    5
}

// 测试时间
fn test_time() {
    println!("RUST test time");
    let now = std::time::SystemTime::now();

    println!("{:?}", now.elapsed().expect(""))
}

// 测试位操作
fn test_bit() {
    let mut bytes = [0u8; 32];
    // let ok = hex::decode("a686d128f4a65574902e5c4c2d795d33c51cd7b822c1cc8014a6ce56939f4d62").expect("msg");
    let ok =
        hex::decode("1a28c7918ab3e1c75571ba16b7a6e689b718a1326c6e89132ed376c4237fd4").expect("msg");
    // println!("ok = {:?}", ok);
    println!("ok = {:?}", ok);
    let mut test: u16 = 1;
    // test = test << 1;
    test = test | ok[0] as u16;
    println!("test = {:?}", test);
    println!("test = {:#b}", test); //输出二进制
    println!("test = {:b}", test); //输出二进制

    println!("");
    let mut i = 0;
    while i < 32 {
        print!("{:10b} ", ok[i]); //输出二进制,b代表二进制,8代表填充长度为8位
        i = i + 1;
    }

    let x = 42;
    let y = "a686d128f4a65574902e5c4c2d795d33c51cd7b822c1cc8014a6ce56939f4d62"
        .as_bytes()
        .to_vec();

    let d = "a686d128f4a65574902e5c4c2d795d33c51cd7b822c1cc8014a6ce56939f4d62"
        .as_bytes()
        .to_vec();
    let z = String::from_utf8(y);
    println!("y = {:?}", z);
    println!("y = {:x}", d[0]);

    let a = std::format!("{:#X}", x);
    println!("{}", &a);
}

// 18 kB
static words: [&str; 2048] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
    "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
    "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
    "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
    "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
    "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
    "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family",
    "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
    "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
    "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
    "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
    "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
    "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
    "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
    "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
    "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor",
    "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum",
    "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable",
    "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak",
    "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic",
    "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose",
    "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
    "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
    "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
    "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose",
    "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
    "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
    "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result",
    "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail",
    "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub",
    "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin",
    "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim",
    "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar",
    "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
    "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun",
    "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear",
    "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test",
    "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue",
    "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss",
    "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
    "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
    "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage",
    "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
    "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo",
];
// 2kB
static word_lengths: [i16; 2048] = [
    7, 7, 4, 5, 5, 6, 6, 8, 6, 5, 6, 8, 7, 6, 7, 4, 8, 7, 6, 3, 6, 5, 7, 6, 5, 3, 6, 7, 6, 5, 5, 7,
    6, 7, 6, 6, 6, 5, 3, 5, 5, 5, 3, 3, 7, 5, 5, 5, 7, 5, 5, 3, 5, 5, 6, 5, 5, 7, 4, 5, 6, 7, 7, 5,
    6, 6, 7, 6, 7, 5, 5, 5, 6, 5, 8, 6, 7, 6, 7, 7, 7, 3, 5, 7, 6, 5, 7, 5, 4, 6, 4, 5, 5, 3, 5, 5,
    4, 6, 7, 6, 6, 5, 3, 8, 6, 7, 3, 6, 7, 5, 6, 6, 6, 7, 4, 6, 6, 8, 7, 7, 5, 6, 4, 6, 4, 6, 7, 7,
    5, 5, 5, 4, 7, 5, 7, 4, 4, 8, 5, 5, 3, 7, 7, 4, 6, 6, 6, 3, 6, 7, 6, 4, 5, 6, 6, 5, 4, 6, 7, 6,
    4, 6, 5, 6, 6, 7, 5, 4, 5, 7, 4, 6, 6, 7, 6, 7, 3, 4, 4, 7, 4, 5, 6, 5, 5, 5, 7, 5, 5, 5, 5, 5,
    7, 6, 4, 4, 5, 5, 4, 4, 4, 4, 4, 5, 4, 5, 6, 6, 6, 4, 6, 6, 3, 3, 7, 5, 5, 5, 5, 5, 6, 5, 6, 5,
    6, 5, 5, 8, 6, 6, 5, 7, 5, 5, 6, 5, 6, 7, 5, 4, 4, 6, 6, 6, 6, 6, 5, 3, 8, 4, 6, 5, 4, 7, 5, 5,
    6, 4, 4, 4, 4, 6, 4, 3, 5, 6, 5, 6, 5, 6, 6, 7, 7, 7, 3, 6, 4, 5, 6, 5, 4, 4, 4, 6, 6, 6, 3, 7,
    5, 8, 6, 6, 5, 7, 4, 7, 6, 6, 6, 7, 6, 7, 5, 5, 8, 6, 5, 7, 6, 5, 4, 5, 5, 6, 4, 6, 5, 7, 5, 5,
    7, 6, 6, 7, 7, 5, 5, 5, 8, 6, 7, 4, 5, 5, 4, 7, 4, 4, 5, 5, 6, 5, 6, 5, 5, 6, 4, 5, 4, 5, 5, 5,
    5, 4, 5, 7, 6, 5, 5, 7, 4, 6, 4, 4, 7, 5, 6, 7, 4, 7, 5, 6, 7, 7, 7, 7, 8, 7, 8, 7, 8, 4, 4, 6,
    4, 5, 4, 4, 7, 4, 6, 5, 7, 6, 6, 6, 5, 6, 5, 6, 5, 4, 5, 5, 6, 5, 5, 5, 6, 5, 4, 7, 5, 5, 6, 4,
    5, 6, 5, 7, 5, 6, 7, 6, 5, 3, 7, 4, 7, 3, 8, 7, 7, 7, 5, 7, 6, 4, 5, 3, 6, 4, 5, 6, 6, 4, 8, 4,
    3, 4, 6, 6, 6, 8, 6, 7, 8, 8, 4, 7, 6, 4, 6, 5, 7, 6, 6, 6, 7, 4, 6, 6, 7, 5, 6, 6, 8, 6, 6, 4,
    7, 7, 6, 6, 7, 6, 6, 7, 4, 7, 5, 4, 6, 4, 6, 7, 7, 7, 6, 8, 6, 4, 8, 8, 7, 4, 7, 8, 7, 8, 6, 6,
    7, 5, 6, 8, 3, 4, 7, 6, 6, 6, 5, 4, 4, 6, 4, 5, 6, 5, 7, 4, 5, 5, 5, 5, 5, 4, 5, 4, 4, 3, 4, 4,
    4, 6, 4, 5, 4, 5, 7, 5, 5, 5, 4, 5, 6, 4, 4, 4, 7, 7, 4, 4, 7, 6, 3, 5, 6, 5, 5, 8, 7, 7, 8, 8,
    5, 4, 6, 6, 7, 6, 7, 6, 7, 5, 6, 5, 3, 7, 7, 5, 6, 7, 6, 6, 7, 5, 6, 6, 6, 6, 6, 5, 6, 5, 8, 7,
    5, 5, 3, 5, 5, 7, 5, 5, 6, 5, 7, 6, 7, 6, 8, 4, 5, 6, 5, 7, 6, 8, 6, 7, 6, 7, 8, 7, 7, 5, 5, 4,
    6, 6, 6, 6, 7, 6, 7, 6, 5, 3, 7, 6, 4, 7, 4, 5, 5, 4, 5, 4, 6, 6, 3, 5, 7, 4, 7, 3, 5, 6, 7, 5,
    8, 7, 8, 7, 3, 4, 4, 6, 5, 8, 5, 5, 3, 5, 7, 5, 6, 4, 4, 6, 5, 4, 4, 6, 6, 4, 4, 5, 6, 4, 3, 7,
    3, 4, 5, 5, 4, 6, 4, 6, 4, 5, 5, 5, 6, 5, 5, 3, 4, 5, 3, 4, 4, 6, 4, 4, 5, 6, 6, 4, 7, 5, 7, 6,
    6, 5, 3, 7, 5, 8, 5, 6, 6, 4, 5, 5, 5, 6, 5, 4, 3, 5, 7, 4, 6, 6, 4, 6, 7, 4, 3, 6, 7, 6, 6, 7,
    3, 4, 4, 6, 5, 4, 7, 6, 5, 6, 7, 7, 5, 5, 4, 6, 6, 7, 4, 4, 4, 6, 5, 5, 5, 7, 5, 5, 5, 5, 4, 4,
    4, 7, 4, 4, 5, 7, 6, 6, 6, 4, 4, 5, 5, 5, 5, 5, 7, 5, 5, 4, 5, 4, 7, 5, 4, 5, 5, 5, 5, 5, 6, 3,
    3, 5, 4, 4, 6, 7, 4, 5, 6, 4, 5, 7, 3, 4, 4, 6, 4, 6, 5, 5, 8, 6, 5, 6, 4, 3, 4, 6, 4, 4, 4, 3,
    4, 7, 5, 6, 4, 4, 7, 6, 4, 5, 4, 4, 4, 6, 5, 8, 4, 5, 4, 5, 3, 4, 5, 6, 5, 7, 6, 4, 6, 5, 4, 7,
    6, 3, 4, 4, 8, 4, 6, 3, 7, 7, 5, 7, 7, 6, 6, 6, 7, 7, 4, 7, 6, 8, 5, 8, 6, 8, 6, 7, 6, 6, 7, 7,
    6, 6, 6, 5, 8, 5, 7, 6, 6, 6, 7, 7, 6, 8, 4, 6, 6, 7, 4, 6, 7, 5, 4, 5, 6, 6, 3, 4, 7, 5, 5, 5,
    3, 4, 4, 7, 3, 5, 5, 4, 6, 6, 4, 4, 8, 4, 4, 7, 3, 4, 3, 6, 4, 7, 4, 3, 7, 4, 6, 4, 4, 5, 5, 4,
    3, 5, 5, 6, 4, 4, 4, 8, 6, 5, 5, 5, 5, 7, 4, 3, 4, 7, 5, 4, 6, 4, 5, 5, 7, 4, 3, 5, 6, 7, 5, 4,
    6, 4, 7, 6, 6, 5, 4, 7, 7, 7, 4, 4, 5, 4, 4, 5, 4, 4, 6, 4, 6, 4, 6, 4, 4, 7, 5, 4, 5, 6, 4, 4,
    7, 4, 6, 4, 5, 5, 7, 6, 5, 5, 6, 6, 7, 3, 5, 6, 4, 4, 4, 5, 4, 6, 3, 6, 7, 5, 7, 6, 5, 6, 5, 6,
    6, 6, 8, 4, 4, 6, 5, 8, 4, 6, 6, 7, 4, 6, 4, 7, 4, 8, 5, 5, 6, 4, 6, 6, 7, 4, 5, 5, 5, 5, 4, 7,
    5, 6, 6, 8, 4, 7, 5, 4, 7, 5, 6, 7, 6, 6, 4, 7, 3, 5, 7, 6, 5, 6, 3, 6, 7, 6, 7, 5, 4, 5, 4, 7,
    8, 6, 6, 5, 8, 5, 4, 5, 4, 6, 4, 8, 6, 6, 8, 5, 4, 6, 6, 7, 4, 5, 4, 6, 6, 5, 6, 6, 4, 4, 4, 8,
    7, 7, 6, 5, 4, 3, 7, 7, 5, 4, 4, 4, 5, 5, 5, 7, 6, 6, 5, 4, 7, 4, 7, 6, 5, 3, 7, 6, 5, 3, 3, 4,
    6, 6, 7, 7, 6, 7, 5, 5, 7, 4, 3, 5, 6, 5, 3, 4, 3, 5, 7, 4, 4, 3, 5, 6, 4, 4, 5, 7, 6, 6, 6, 5,
    7, 5, 8, 5, 6, 8, 6, 7, 5, 7, 5, 6, 7, 4, 4, 4, 3, 5, 6, 6, 5, 4, 6, 4, 4, 6, 4, 5, 5, 5, 7, 5,
    6, 6, 4, 6, 5, 4, 5, 4, 7, 6, 7, 5, 4, 7, 5, 6, 4, 7, 7, 3, 7, 6, 6, 6, 7, 6, 6, 3, 5, 5, 6, 8,
    5, 6, 7, 5, 3, 6, 4, 5, 4, 7, 4, 6, 5, 5, 5, 6, 7, 5, 4, 6, 6, 5, 4, 6, 4, 4, 5, 5, 4, 6, 4, 4,
    4, 7, 7, 8, 8, 4, 6, 7, 7, 6, 5, 8, 6, 7, 6, 7, 7, 6, 7, 5, 5, 7, 5, 8, 6, 7, 5, 7, 7, 7, 6, 7,
    7, 7, 5, 8, 7, 7, 5, 7, 6, 7, 4, 4, 5, 7, 5, 5, 5, 8, 6, 7, 5, 4, 3, 6, 7, 7, 7, 7, 8, 5, 4, 4,
    5, 6, 7, 4, 4, 5, 5, 4, 4, 5, 5, 4, 5, 6, 5, 5, 4, 4, 6, 5, 3, 5, 5, 4, 6, 5, 7, 6, 7, 6, 6, 7,
    6, 7, 6, 6, 6, 6, 7, 6, 5, 7, 6, 4, 6, 8, 6, 6, 6, 5, 4, 6, 6, 6, 7, 6, 7, 6, 8, 6, 8, 8, 6, 6,
    7, 6, 7, 6, 6, 6, 6, 3, 6, 4, 4, 4, 5, 5, 5, 5, 4, 4, 6, 4, 6, 5, 5, 4, 5, 5, 6, 6, 7, 4, 6, 4,
    4, 6, 5, 5, 5, 5, 6, 4, 3, 4, 3, 6, 5, 3, 6, 7, 4, 4, 5, 6, 5, 4, 6, 4, 6, 4, 7, 7, 5, 7, 4, 3,
    5, 4, 5, 7, 5, 6, 6, 7, 8, 8, 5, 5, 6, 6, 5, 3, 6, 6, 4, 6, 6, 7, 8, 4, 4, 7, 6, 4, 7, 6, 5, 8,
    6, 7, 7, 6, 5, 5, 6, 5, 7, 5, 4, 5, 7, 6, 5, 5, 4, 6, 5, 4, 5, 4, 5, 8, 5, 6, 5, 7, 3, 7, 4, 4,
    5, 5, 4, 6, 4, 5, 6, 7, 6, 5, 4, 5, 6, 7, 3, 4, 5, 6, 3, 5, 4, 5, 5, 4, 4, 5, 7, 5, 5, 6, 4, 6,
    4, 4, 5, 5, 5, 5, 5, 6, 5, 5, 4, 5, 4, 4, 6, 6, 4, 4, 4, 5, 7, 5, 8, 5, 7, 4, 4, 5, 4, 4, 5, 4,
    6, 5, 5, 5, 7, 5, 5, 7, 5, 5, 5, 6, 5, 6, 5, 4, 6, 5, 5, 7, 5, 5, 4, 5, 6, 6, 3, 6, 7, 8, 6, 7,
    5, 5, 6, 5, 5, 5, 5, 4, 5, 5, 4, 4, 6, 5, 5, 5, 5, 7, 5, 5, 5, 5, 8, 6, 6, 6, 8, 7, 5, 7, 5, 7,
    6, 6, 7, 4, 6, 6, 5, 7, 4, 6, 3, 5, 6, 5, 6, 7, 4, 7, 5, 8, 8, 6, 7, 7, 7, 5, 4, 5, 5, 5, 5, 4,
    5, 6, 5, 6, 7, 5, 6, 5, 6, 3, 4, 6, 4, 4, 4, 6, 4, 5, 6, 4, 5, 4, 4, 3, 6, 6, 4, 4, 4, 4, 5, 4,
    5, 4, 6, 5, 4, 5, 4, 7, 5, 6, 5, 5, 7, 6, 4, 5, 4, 6, 4, 4, 3, 5, 6, 5, 5, 7, 5, 7, 3, 8, 6, 5,
    6, 8, 4, 6, 7, 4, 5, 3, 5, 6, 5, 7, 8, 4, 5, 7, 6, 5, 4, 3, 5, 5, 7, 6, 5, 8, 4, 5, 6, 4, 5, 4,
    5, 5, 5, 5, 7, 4, 4, 6, 7, 5, 4, 5, 7, 5, 5, 3, 4, 7, 6, 4, 6, 6, 4, 6, 6, 6, 5, 4, 5, 3, 4, 7,
    4, 8, 6, 7, 5, 7, 5, 4, 6, 6, 7, 7, 6, 4, 8, 7, 6, 5, 7, 6, 6, 7, 6, 4, 5, 5, 5, 4, 5, 3, 4, 6,
    7, 5, 7, 6, 6, 5, 5, 6, 5, 3, 6, 5, 7, 4, 5, 7, 6, 6, 7, 5, 4, 6, 7, 4, 6, 7, 6, 7, 7, 7, 5, 4,
    7, 7, 6, 7, 5, 4, 5, 6, 5, 5, 5, 5, 4, 7, 6, 4, 6, 4, 5, 4, 4, 4, 6, 4, 7, 4, 7, 4, 4, 5, 5, 4,
    3, 6, 6, 4, 6, 7, 3, 7, 7, 5, 7, 4, 3, 5, 4, 5, 5, 4, 5, 4, 7, 4, 5, 4, 4, 4, 3, 6, 4, 4, 4, 6,
    6, 4, 6, 4, 4, 7, 4, 5, 6, 4, 4, 4, 4, 5, 5, 5, 4, 5, 7, 5, 5, 5, 4, 4, 6, 3, 5, 5, 5, 4, 4, 3,
];
