use serde_json::*;
use sp_core;
use sp_core::Pair;
use sp_core::hexdisplay::AsBytesRef;
use sp_core::sr25519;
use tungstenite::{connect, Message, WebSocket};
use url::Url;
use parity_scale_codec::{Decode, Encode};
use clap::Parser;
use tungstenite::handshake::client::Response;
use tungstenite::stream::MaybeTlsStream;
use std::io::Write;
use std::net::TcpStream;

#[derive(Parser, Debug)]
struct Args {
   /// Name of the person to greet
   #[arg(short, long)]
   name: String,

   /// Number of times to greet
   #[arg(short, long, default_value_t = 1)]
   count: u8,
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

enum SelectCall{
    Mint = 1,
    Transfer = 2,
    State = 3,
    Exit = 4,
    InvalidOption = 5,
}

fn main() {
    std::process::Command::new("clear").status().unwrap();
    println!("Hello my friend!");
    println!("Welcome to the interactive CLI of the Substrate Node");
    loop {
        basic_cli();
    }
}


fn basic_cli(){
    //interative CLI
    println!("------------------------------------");
    println!("Choose one of the following options:");
    println!("1. Mint");
    println!("2. Transfer");
    println!("3. Get State");
    println!("4. Exit CLI");
    print!("Option: ");
    std::io::stdout().flush().expect("");
    let mut option = String::new();
    std::io::stdin().read_line(&mut option).expect("Failed to read line");
    let option: u8 = option.trim().parse().expect("Please type a number!");
    
    //convert option to selectcall enum
    let select_call = match option {
        1 => SelectCall::Mint,
        2 => SelectCall::Transfer,
        3 => SelectCall::State,
        4 => SelectCall::Exit,
        _ => SelectCall::InvalidOption,
    };

    match select_call {
        SelectCall::Mint => {
            // ask for the key
            println!("--- Mint data ---");
            println!("NOTE: Your destination 'address' would be your public key.");
            println!("");

            print!("Mnemonic of destination key/address : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");
            let mnemonic: String = key.trim().parse().expect("Please type a string");

            print!("Amount : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");

            let amount: u128 = key.trim().parse().expect("Please type a string");

            let pair = get_pair(mnemonic.to_string());
            println!("Your public key is : {:?} ", hex::encode(pair.public().0));
            do_mint(pair, amount).expect("error on mint");
            
            println!("Ok mint");
        },
        SelectCall::Transfer => {
            println!("");
            println!("--- Transfer data ---");
            println!("NOTE: Your destination 'address' would be your public key.");
            println!("");

            print!("Mnemonic of origin key/address : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");
            let mnemonic: String = key.trim().parse().expect("Please type a string");

            print!("Public destination Key (same as Address Destination) : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");

            let public_key: String = key.trim().parse().expect("Please type a string");
            let public_key_decode = hex::decode(public_key).expect("error on decode");
            let destination_public_key:[u8;32] = public_key_decode[..].try_into().expect("error on decode");

            print!("Amount : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");

            let amount: u128 = key.trim().parse().expect("Please type a string");

            let pair = get_pair(mnemonic.to_string());
            println!("Your public origin key is : {:?} ", hex::encode(pair.public().0.encode()));
            do_tranfer(pair, destination_public_key ,amount).expect("error on transfer");

            println!("Ok transfer");
        },
        SelectCall::State => {
            // ask for the key}
            println!("--- Get data from state ---");

            print!("Key state : ");
            std::io::stdout().flush().expect("");
            let mut key = String::new();
            std::io::stdin().read_line(&mut key).expect("Failed to read line");

            let key: String = key.trim().parse().expect("Please type a string");
            let key_decode = hex::decode(key).expect("error on decode");
            let value = get_value(&key_decode[..]);
            println!("The value is : {:?}", value);
        },
        SelectCall::InvalidOption => {
            std::process::Command::new("clear").status().unwrap();
            println!("Invalid option !");
        },
        SelectCall::Exit => {
            println!("Bye bye! have a nice day :)");
            std::process::exit(0);
        },
    }
    println!("");
    
}

fn create_socket() -> (Socket, Response){
    connect(Url::parse("ws://localhost:9944").unwrap()).expect("Can't connect to the server")
}

fn do_mint(pair: sr25519::Pair, amount: u128) -> Result<String>{
    let call = Call::Mint(pair.public().0, amount);
    Ok(send_extrincis(call, &pair))
}

fn do_tranfer(pair: sr25519::Pair, destination_address:[u8;32] ,amount: u128) -> Result<String>{
    let call_transfer = Call::Transfer(pair.public().0, destination_address, amount);
    Ok(send_extrincis(call_transfer, &pair))
}

fn get_value(position: &[u8]) -> u128{
    let extrinsic_encode = hex::encode(&position);

    let mut data:String = "0x".to_string();
    data.push_str(extrinsic_encode.as_str());

    let json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "state_getStorage",
        "params": [data]
    });

    //Send the message to the server
    let txt = send_message(json.to_string());

    let txt_clean = txt[3..txt.len()-1].to_string();
    let txt_decode = hex::decode(txt_clean).expect("error on decode");

    let result = u128::decode(&mut &txt_decode[..]).unwrap();
    result
}

fn send_extrincis(call:Call, pair: &sr25519::Pair) -> String{
    // create and convert the signature to H512
    let signature = generate_signature(&pair, &call);
    let final_signature:sp_core::H512 = signature.0.into();

    // generate the BasicExtrinsic
    let extrinsic = BasicExtrinsic(call, Some(PayLoadVerify {signature: final_signature, public_key: pair.public().0.into()}));

    // encode and convert to hex the BasicExtrinsic
    let extrinsic_encode = hex::encode(&extrinsic.encode());

    // generate the JSON message
    let data = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "author_submitExtrinsic",
        "params": [extrinsic_encode]
    });

    //Send the message to the server
    send_message(data.to_string())
}

fn send_message(message: String) -> String{
    let (mut socket, _) = create_socket();

    // send the message
    socket.write_message(Message::Text(message)).unwrap();

    loop {
        // read binary message or text message
        let msg = socket.read_message().unwrap();
        match msg {
            Message::Text(txt) => {
                //return result of the text message
                let value: serde_json::Value =serde_json::from_str(&txt).expect("Can't parse to JSON");
                return value["result"].to_string();
            },
            Message::Close(_) => {
                return "".to_string();
            },
            _ => {
            }
        }
    }
}

/* fn generate_key() -> sr25519::Pair{
    let (pair, memmonic, _) = sp_core::sr25519::Pair::generate_with_phrase(None);
    println!("{}", memmonic);
    pair
} */

fn get_pair(memmonic:String) -> sr25519::Pair{
    let (pair, _) = sp_core::sr25519::Pair::from_phrase(&memmonic,None).unwrap();
    pair
}

fn generate_signature(pair:&sr25519::Pair, call: &Call) -> sr25519::Signature {
    let call_encode = call.encode();
    let signature = pair.sign(call_encode.as_bytes_ref());

    signature
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, parity_util_mem::MallocSizeOf))]
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum Call {
	Transfer([u8; 32], [u8; 32], u128),
	Upgrade(Vec<u8>),
	SetFee(u128),
	SetReward(u128),
	Mint([u8; 32], u128),
}

#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone)]
pub struct BasicExtrinsic(
	Call,
	Option<PayLoadVerify>
);

#[derive(Debug, Encode, Decode, PartialEq, Eq, Clone)]
pub struct PayLoadVerify {
	signature: sp_core::H512, // signature
	public_key: sp_core::H256 // public key
}