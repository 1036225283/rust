use hex;
use ocl::builders::ContextProperties;
use ocl::enums::ArgVal;
use ocl::prm::cl_ulong;
use ocl::{core, flags};
use rayon::prelude::*;
use serde::Deserialize;
use std::env;
use std::ffi::CString;
use std::fs;
use std::sync::mpsc::{self, SyncSender};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

#[macro_use]
extern crate lazy_static;
lazy_static! {
    static ref WORDS: Mutex<Vec<Vec<u16>>> = Mutex::new(vec![]);
    static ref CONFIG_INPUT: Mutex<Vec<String>> = Mutex::new(vec![]);
}

#[derive(Deserialize, Debug)]
struct WorkResponse {
    indices: Vec<u128>,
    offset: u128,
    batch_size: u64,
}

// 直接在本机生成助记词
struct Word {
    // 备选数据
    optional: Vec<u16>,
    // 输入数据
    input: Vec<u16>,
    // 输入数据对应的索引
    column_index: u16,
    inner_index: u16,
    // 输出数据
    output: Vec<u16>,
    // 单词索引
    word_index: u16,
    // 索引数据
    indexs: Vec<u16>,
}

impl Default for Word {
    fn default() -> Self {
        Word {
            optional: Vec::new(),
            column_index: 0,
            inner_index: 0,
            word_index: 0,
            input: Vec::new(),
            output: Vec::new(),
            indexs: Vec::new(),
        }
    }
}
impl Word {
    fn set_input(&mut self, v: Vec<u16>) {
        self.input = v;
        self.column_index = 0;
        self.inner_index = 0;
    }

    fn show_input(&mut self) {
        println!("input {:?}", self.input)
    }

    // 判断是否还有其他下一个助记词
    fn next(&mut self) -> bool {
        if self.inner_index
            < WORDS.lock().unwrap()[self.input[self.column_index as usize] as usize].len() as u16
        {
            return true;
        }

        self.column_index = self.column_index + 1;
        self.inner_index = 0;

        if self.column_index < (self.input.len() as u16) {
            return true;
        } else {
            return false;
        }
    }

    // 获取下一个助记词
    fn next_data(&mut self) -> u16 {
        // 先取备选词,如果备选词没了,再选下一个序列
        // input存储序列
        // words存储真正的助记单词
        // 从input_index存储已经遍历的位置中取出序列索引
        //

        // println!(
        //     "the input1 = {:?}, column_index = {}, inner_index = {} ,len = {}",
        //     self.input,
        //     self.input[self.column_index as usize],
        //     self.inner_index,
        //     WORDS.lock().unwrap()[self.input[self.column_index as usize] as usize].len()
        // );
        if self.inner_index
            < WORDS.lock().unwrap()[self.input[self.column_index as usize] as usize].len() as u16
        {
            let data = WORDS.lock().unwrap()[self.input[self.column_index as usize] as usize]
                [self.inner_index as usize];
            self.inner_index = self.inner_index + 1;
            return data;
        } else {
            // self.column_index = self.column_index + 1;
            // println!(
            //     "the input = {:?}, column_index = {}, inner_index = {}",
            //     self.input, self.input[self.column_index as usize], self.inner_index
            // );
            self.inner_index = 0;

            let data = WORDS.lock().unwrap()[self.input[self.column_index as usize] as usize]
                [self.inner_index as usize];
            return data;
        }
    }

    // 获取下一级的输入
    fn child_input_data(&mut self) -> Vec<u16> {
        self.output = self.input.clone();
        // println!(
        //     "the output = {:?}, column_index = {}",
        //     self.output, self.column_index
        // );
        self.output.remove((self.column_index) as usize);
        self.output.clone()
    }

    // 设置备选词
    fn set_optional_from_str(&mut self, s: &str) {
        let input_data: Vec<&str> = s.split(" ").collect();
        let mut i = 0;
        while i < input_data.len() {
            let index = get_word_index(input_data[i]);
            self.optional.push(index);
            i = i + 1;
        }
    }

    // 最后一个单词的备选词
    fn set_optional(&mut self, v: Vec<u16>) {
        let mut i = 0;
        while i < v.len() {
            self.optional.push(v[i]);
            i = i + 1;
        }
    }

    // 设置2048为备选词
    fn set_optional_all(&mut self) {
        let mut i = 0;
        while i < 2048 {
            self.optional.push(i);
            i = i + 1;
        }
    }

    // 根据GPU的数量来设置备选词
    fn set_optional_for_group(&mut self, s: &str) {
        let input_group: Vec<&str> = s.split(" ").collect();
        let group_total: u16 = input_group[0].parse().unwrap();
        let group_index: u16 = input_group[1].parse().unwrap();
        let len = 2048 / group_total;
        let mut i = 0;
        while i < len {
            self.optional.push((group_index * len + i) as u16);
            i = i + 1;
        }
        // println!("set_optional_for_group = {:?}", self.optional);
    }

    // 设置助记词索引
    fn set_word_index(&mut self, word_index: u16) {
        self.word_index = word_index;
    }

    // 设置助记词索引数组
    fn set_indexs(&mut self, indexs: Vec<u16>) {
        self.indexs = indexs;
    }

    fn modify_indexs(&mut self) {
        self.indexs[self.word_index as usize] = self.input[self.column_index as usize];
    }
}

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

    // 在这里加载所有的代码
    let (tx, rx) = mpsc::sync_channel(1000);

    let handle = thread::spawn(move || {
        create_words_from_file(tx.clone());
        // thread::sleep(Duration::from_millis(100));
        println!("create finsh... ...");
    });

    let address = create_address();

    loop {
        let received = rx.recv().unwrap();
        println!("the received.len = {}", received.len() / 32);

        let now = std::time::SystemTime::now();

        // let flag = 2;
        // if flag > 1 {
        //     println!("RUST flag > 1");
        // }

        let input_entropy_size: cl_ulong = (received.len() as u64 / 32);
        let items: u64 = input_entropy_size;

        let mut out_mnemonic = vec![0u8; 256];

        let input_entropy_buf = unsafe {
            core::create_buffer(
                &context,
                flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                received.len(),
                Some(&received),
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

        if out_mnemonic[0] != 0 {
            let s = match String::from_utf8((&out_mnemonic[0..256]).to_vec()) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            println!(
                "RUST SUCCESS !!! the out mnemonic = {}",
                String::from_utf8(out_mnemonic).expect("msg")
            );
            std::process::exit(0)
        }

        println!("RUST use time {:?}, ", now.elapsed().expect(""));

        // println!("RUST this is end ");

        // assert!(flag < 1);
        // println!("RUST this assert ");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("the input param = {:?}", args);

    let content = fs::read_to_string(args[1].to_string()).unwrap();
    let input_data: Vec<&str> = content.split("\n").collect();

    for s in &input_data {
        CONFIG_INPUT.lock().unwrap().push(s.to_string());
    }
    println!("the CONFIG = {:?}", CONFIG_INPUT.lock().unwrap());

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

    // words_to_32byte("anger stem hobby giraffe cable source episode remove border acquire connect brief syrup stay success badge angry ahead fame tone seat arm army basic");
    // test_redis();
    // test_time();
    // test_bit();

    let s = "hello";

    // let (tx, rx) = mpsc::channel();
    // let (tx, rx) = mpsc::sync_channel(10);
    // create_words_from_file(tx.clone());

    // let handle = thread::spawn(move || {
    //     let mut i = 0;
    //     loop {
    //         println!("spawned thread print {}, s = {}", i, s);
    //         tx.send(String::from("hi")).unwrap();

    //         thread::sleep(Duration::from_millis(1000));
    //         i = i + 1;
    //     }
    // });
    // for i in 0..3 {
    //     println!("main thread print {}", i);
    //     thread::sleep(Duration::from_millis(1));
    // }

    // loop {
    //     thread::sleep(Duration::from_millis(100));

    //     let received = rx.recv().unwrap();
    //     println!("Got: {}", received);
    // }

    // handle.join().unwrap();
}

// 创建20字节的地址数组
fn create_address() -> Vec<u8> {
    // let address = hex::decode("7127e93651CC9d3AD3c0e5499Dba43cB765783E2").expect("msg");
    let address = hex::decode(&CONFIG_INPUT.lock().unwrap()[11]).expect("msg");
    address
}

// 获取助记词的index
fn get_word_index(s: &str) -> u16 {
    let index = words.iter().position(|&x| x.eq(s));
    let i = index.expect("get_word_index failure") as u16;
    i
}

// 助记词转换成助记词索引
fn word_to_word_index(s: &str) -> Vec<u16> {
    let input_data: Vec<&str> = s.split(" ").collect();
    let mut word_index: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < input_data.len() {
        let index = get_word_index(input_data[i]);
        word_index.push(index);
        i = i + 1;
    }
    return word_index;
}

// 助记词转换成vec[u8,32]
fn words_to_32byte(input_word: &str) -> Vec<u8> {
    // let input_word = String::from("anger stem hobby giraffe cable source episode remove border acquire connect brief syrup stay success badge angry ahead fame tone seat arm army basic");
    println!("the input word = {:?}", input_word);

    let pos: Vec<&str> = input_word.split(" ").collect();

    let mut i = 0;
    let mut input_word_index = vec![0u16; 24];

    while i < 24 {
        input_word_index[i] = get_word_index(pos[i]);
        println!(
            "{} word = {} index = {} {:b}",
            i, pos[i], input_word_index[i], input_word_index[i]
        );
        i = i + 1;
    }
    let entropy = words_index_to_32byte(input_word_index);

    entropy
}

fn words_index_to_32byte(input_word_index: Vec<u16>) -> Vec<u8> {
    // 先填充前132位, 每个单词11位,要映射的到8位上面去
    let mut entropy = vec![0u8; 32];

    entropy[0] = (input_word_index[0] >> 3) as u8;

    entropy[1] = ((input_word_index[0] & 7) << 5) as u8 | (input_word_index[1] >> 6) as u8;

    entropy[2] = ((input_word_index[1] & 63) << 2) as u8 | (input_word_index[2] >> 9) as u8;
    entropy[3] = (input_word_index[2] >> 1) as u8;
    entropy[4] = ((input_word_index[2] & 1) << 7) as u8 | (input_word_index[3] >> 4) as u8;
    entropy[5] = ((input_word_index[3] & 15) << 4) as u8 | (input_word_index[4] >> 7) as u8;
    entropy[6] = ((input_word_index[4] & 127) << 1) as u8 | (input_word_index[5] >> 10) as u8;
    entropy[7] = (input_word_index[5] >> 2) as u8;
    entropy[8] = ((input_word_index[5] & 3) << 6) as u8 | (input_word_index[6] >> 5) as u8;
    entropy[9] = ((input_word_index[6] & 31) << 3) as u8 | (input_word_index[7] >> 8) as u8;
    entropy[10] = input_word_index[7] as u8;

    // 接下来就是重复操作
    entropy[11] = (input_word_index[8] >> 3) as u8;
    entropy[12] = ((input_word_index[8] & 7) << 5) as u8 | (input_word_index[9] >> 6) as u8;
    // println!("y = {:b}", (input_word_index[8]));
    // println!("y = {:b}", (input_word_index[8] & 7));
    // println!(
    //     "c = {:b}",
    //     ((input_word_index[8] & 7) << 5) as u8 | ((input_word_index[9] >> 6) as u8)
    // );

    entropy[13] = ((input_word_index[9] & 63) << 2) as u8 | (input_word_index[10] >> 9) as u8;
    entropy[14] = (input_word_index[10] >> 1) as u8;
    entropy[15] = ((input_word_index[10] & 1) << 7) as u8 | (input_word_index[11] >> 4) as u8;
    entropy[16] = ((input_word_index[11] & 15) << 4) as u8 | (input_word_index[12] >> 7) as u8;
    entropy[17] = ((input_word_index[12] & 127) << 1) as u8 | (input_word_index[13] >> 10) as u8;
    entropy[18] = (input_word_index[13] >> 2) as u8;
    entropy[19] = ((input_word_index[13] & 3) << 6) as u8 | (input_word_index[14] >> 5) as u8;
    entropy[20] = ((input_word_index[14] & 31) << 3) as u8 | (input_word_index[15] >> 8) as u8;
    entropy[21] = input_word_index[15] as u8;

    // 再次重复操作
    entropy[22] = (input_word_index[16] >> 3) as u8;
    entropy[23] = ((input_word_index[16] & 7) << 5) as u8 | (input_word_index[17] >> 6) as u8;
    entropy[24] = ((input_word_index[17] & 63) << 2) as u8 | (input_word_index[18] >> 9) as u8;
    entropy[25] = (input_word_index[18] >> 1) as u8;
    entropy[26] = ((input_word_index[18] & 1) << 7) as u8 | (input_word_index[19] >> 4) as u8;
    entropy[27] = ((input_word_index[19] & 15) << 4) as u8 | (input_word_index[20] >> 7) as u8;
    entropy[28] = ((input_word_index[20] & 127) << 1) as u8 | (input_word_index[21] >> 10) as u8;
    entropy[29] = (input_word_index[21] >> 2) as u8;
    entropy[30] = ((input_word_index[21] & 3) << 6) as u8 | (input_word_index[22] >> 5) as u8;
    // entropy[31] = ((input_word_index[22] & 31) << 3) as u8 | (input_word_index[23] >> 8) as u8;
    entropy[31] = ((input_word_index[22] & 31) << 3) as u8 | (input_word_index[23]) as u8;

    // let mut k = 0;
    // print!("words_to_32byte ");
    // while k < 32 {
    //     print!("{:x}", entropy[k]);
    //     // println!("test = {:b}", test); //输出二进制

    //     k = k + 1;
    // }
    // println!("");

    entropy
}

// 9个单词的次序是固定的
fn create_words_from_file(tx: SyncSender<Vec<u8>>) {
    let word_index_12 = word_to_word_index(&CONFIG_INPUT.lock().unwrap()[0]);
    let GPU_SIZE = 256000;

    println!("word_index_12 = {:?}", word_index_12);

    // 初始化
    let mut input: Vec<u16> = Vec::new();
    let mut i: u16 = 0;
    while i < 11 {
        input.push(i);
        i = i + 1;
    }

    // if i > 0 {
    //     return;
    // }

    // 从外部加载每个助记词的input
    let mut word0 = Word::default();
    let mut word1 = Word::default();
    let mut word2 = Word::default();
    let mut word3 = Word::default();
    let mut word4 = Word::default();
    let mut word5 = Word::default();
    let mut word6 = Word::default();
    let mut word7 = Word::default();
    let mut word8 = Word::default();
    let mut word9 = Word::default();
    let mut word10 = Word::default();
    let mut word11 = Word::default();

    word0.set_input(input);
    word0.show_input();
    // 9个助记词的备选词
    word0.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[1]);
    word1.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[2]);
    word2.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[3]);
    word3.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[4]);
    word4.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[5]);
    word5.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[6]);
    word6.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[7]);
    word7.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[8]);
    word8.set_optional_from_str(&CONFIG_INPUT.lock().unwrap()[9]);
    // 第10个助记词的备选词是2048个单词
    word9.set_optional_all();
    // word9.set_optional(vec![9]);
    // 第11个助记词的备选词的2048的几分之几,分母是GPU的数量
    word10.set_optional_for_group(&CONFIG_INPUT.lock().unwrap()[10]);
    // word10.set_optional(vec![10]);
    // 第12个助记词的备选是1,2,3,4,5,6,7
    word11.set_optional(vec![1, 2, 3, 4, 5, 6, 7]);

    // 设置助记词索引
    word0.set_word_index(0);
    word1.set_word_index(1);
    word2.set_word_index(2);
    word3.set_word_index(3);
    word4.set_word_index(4);
    word5.set_word_index(5);
    word6.set_word_index(6);
    word7.set_word_index(7);
    word8.set_word_index(8);
    word9.set_word_index(9);
    word10.set_word_index(10);
    word11.set_word_index(11);

    WORDS.lock().unwrap().push(word0.optional.clone());
    WORDS.lock().unwrap().push(word1.optional.clone());
    WORDS.lock().unwrap().push(word2.optional.clone());
    WORDS.lock().unwrap().push(word3.optional.clone());
    WORDS.lock().unwrap().push(word4.optional.clone());
    WORDS.lock().unwrap().push(word5.optional.clone());
    WORDS.lock().unwrap().push(word6.optional.clone());
    WORDS.lock().unwrap().push(word7.optional.clone());
    WORDS.lock().unwrap().push(word8.optional.clone());
    WORDS.lock().unwrap().push(word9.optional.clone());
    WORDS.lock().unwrap().push(word10.optional.clone());
    WORDS.lock().unwrap().push(word11.optional.clone());

    let mut the_i = 0;
    while the_i < 12 {
        println!("WORDS{} = {:?}", the_i, WORDS.lock().unwrap()[the_i]);
        the_i = the_i + 1;
    }

    println!("len = {}", WORDS.lock().unwrap().len());

    let now = std::time::SystemTime::now();

    // 助记词数据
    let mut the_data = vec![0u16; 12];
    // 助记词索引
    let the_index = vec![0u16; 11];

    // 性能测试
    let mut the_datas: Vec<u8> = Vec::new();

    // 数据记数
    let mut count = 0;

    while word0.next() {
        the_data[0] = word0.next_data();

        word0.set_indexs(the_index.clone());
        word0.modify_indexs();

        word1.set_input(word0.child_input_data());
        while word1.next() {
            the_data[1] = word1.next_data();

            word1.set_indexs(word0.indexs.clone());
            word1.modify_indexs();
            if !judge_order(word1.indexs.clone(), 1) {
                continue;
            }
            word2.set_input(word1.child_input_data());
            while word2.next() {
                the_data[2] = word2.next_data();

                word2.set_indexs(word1.indexs.clone());
                word2.modify_indexs();
                if !judge_order(word2.indexs.clone(), 2) {
                    continue;
                }
                word3.set_input(word2.child_input_data());
                while word3.next() {
                    the_data[3] = word3.next_data();

                    word3.set_indexs(word2.indexs.clone());
                    word3.modify_indexs();
                    if !judge_order(word3.indexs.clone(), 3) {
                        continue;
                    }
                    word4.set_input(word3.child_input_data());
                    while word4.next() {
                        the_data[4] = word4.next_data();

                        word4.set_indexs(word3.indexs.clone());
                        word4.modify_indexs();
                        if !judge_order(word4.indexs.clone(), 4) {
                            continue;
                        }
                        word5.set_input(word4.child_input_data());
                        while word5.next() {
                            the_data[5] = word5.next_data();

                            word5.set_indexs(word4.indexs.clone());
                            word5.modify_indexs();
                            if !judge_order(word5.indexs.clone(), 5) {
                                continue;
                            }
                            word6.set_input(word5.child_input_data());
                            while word6.next() {
                                the_data[6] = word6.next_data();

                                word6.set_indexs(word5.indexs.clone());
                                word6.modify_indexs();
                                if !judge_order(word6.indexs.clone(), 6) {
                                    continue;
                                }
                                word7.set_input(word6.child_input_data());
                                while word7.next() {
                                    the_data[7] = word7.next_data();

                                    word7.set_indexs(word6.indexs.clone());
                                    word7.modify_indexs();
                                    if !judge_order(word7.indexs.clone(), 7) {
                                        continue;
                                    }
                                    word8.set_input(word7.child_input_data());
                                    while word8.next() {
                                        the_data[8] = word8.next_data();

                                        word8.set_indexs(word7.indexs.clone());
                                        word8.modify_indexs();
                                        if !judge_order(word8.indexs.clone(), 8) {
                                            continue;
                                        }
                                        word9.set_input(word8.child_input_data());
                                        while word9.next() {
                                            the_data[9] = word9.next_data();

                                            word9.set_indexs(word8.indexs.clone());
                                            word9.modify_indexs();
                                            if !judge_order(word9.indexs.clone(), 9) {
                                                continue;
                                            }
                                            word10.set_input(word9.child_input_data());
                                            while word10.next() {
                                                the_data[10] = word10.next_data();

                                                word10.set_indexs(word9.indexs.clone());
                                                word10.modify_indexs();
                                                if !judge_order(word10.indexs.clone(), 10) {
                                                    continue;
                                                }
                                                let mut data_11 = 0;
                                                while data_11 <= 7 {
                                                    the_data[11] = data_11;
                                                    data_11 = data_11 + 1;
                                                    let mut word_index_12_copy =
                                                        word_index_12.clone();
                                                    let mut index_9 = 0;
                                                    while index_9 < the_data.len() {
                                                        word_index_12_copy.push(the_data[index_9]);
                                                        index_9 = index_9 + 1;
                                                    }

                                                    let entity =
                                                        words_index_to_32byte(word_index_12_copy);

                                                    // 拿到最终的助记词索引

                                                    if count < GPU_SIZE {
                                                        count = count + 1;
                                                        let mut index_32: u16 = 0;
                                                        while index_32 < 32 {
                                                            the_datas
                                                                .push(entity[index_32 as usize]);
                                                            index_32 = index_32 + 1;
                                                        }
                                                        // println!("llen = {}", the_datas.len())
                                                    } else {
                                                        count = 0;
                                                        // println!(
                                                        //     "RUST use time {:?}, len = {}",
                                                        //     now.elapsed().expect(""),
                                                        //     the_datas.len()
                                                        // );

                                                        tx.send(the_datas.clone()).unwrap();
                                                        the_datas.clear();
                                                        // thread::sleep(Duration::from_millis(
                                                        //     1000000000,
                                                        // ));
                                                        println!("the_indexs = {:?}", the_data);
                                                    }
                                                    // println!("the data = {:?}", the_data);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // println!("the child data = {:?}", word0.output);
    }

    println!("last size = {}", the_datas.len());
    tx.send(the_datas).unwrap();

    // println!("index = {:?}", word0.output);
}

// 判断9个助记词的顺序是否正常
fn judge_order(indexs: Vec<u16>, end: usize) -> bool {
    let mut i = 1;
    let mut before = indexs[0];
    while i <= end {
        // if self.indexs[i] == before {
        //     return false;
        // }

        if indexs[i] == 9 || indexs[i] == 10 {
            i = i + 1;
            continue;
        }

        if before == 9 || before == 10 {
            before = indexs[i];
            i = i + 1;
            continue;
        }

        if before >= indexs[i] {
            return false;
        } else {
            before = indexs[i];
        }
        i = i + 1;
    }

    return true;
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
