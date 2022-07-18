//! Drawing cards using VRFs

extern crate schnorrkel;
use std::thread;

use merlin::Transcript;
use schnorrkel::{
	vrf::{VRFInOut, VRFPreOut, VRFProof},
	Keypair, PublicKey,
};

use std::sync::mpsc;

const NUM_DRAWS: u8 = 8;
const NUM_CARDS: u16 = 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Draw {
	value: u8,
	thread_id: u8,
	signature: [u8; 97],
	public_key: PublicKey,
}

fn main() {
	let (tx, rx) = mpsc::channel();

	let vrf_seed = &[0u8; 32];

	// call draw calls

	// perform the below operation in 5 different threads, and find the winning thread
	let mut winning_thread: i32 = 0;
	let mut winning_thread_score: u16 = 0;

	for i in 0..5 {
		let tx_foo = tx.clone();

		thread::spawn(move || {
			let mut csprng = rand_core::OsRng;

			let keypair = Keypair::generate_with(&mut csprng);

			let draw = draws(&keypair, vrf_seed);

			let (card, signature) = draw[0];

			// reveal cards we must call receive

			let public_key = keypair.public;

			tx_foo
				.send(Draw { value: card as u8, thread_id: i as u8, signature, public_key })
				.unwrap();
		});
	}

	// receive the winning thread
	// wait till all threads terminate and get the winning thread
	for _ in 0..5 {
		let ans = rx.recv().unwrap();

		// verify the signature
		let reveal_card = recieve(&ans.public_key, &ans.signature, vrf_seed);

		// extract from Option
		let reveal_card = reveal_card.unwrap();

		if reveal_card > winning_thread_score {
			winning_thread = ans.thread_id as i32;
			winning_thread_score = ans.value as u16;
		}
	}

	// print the output
	println!("The winning thread is: {:#?}", winning_thread);
	println!("The winning thread score is: {}", winning_thread_score);
}

/// Processes VRF inputs, checking validity of the number of draws
fn draw_transcript(seed: &[u8; 32], draw_num: u8) -> Option<Transcript> {
	if draw_num > NUM_DRAWS {
		return None;
	}
	let mut t = Transcript::new(b"Card Draw Transcript");
	t.append_message(b"seed", seed);
	t.append_u64(b"draw", draw_num as u64);
	Some(t)
}

/// Computes actual card draw from VRF inputs & outputs together
fn find_card(io: &VRFInOut) -> Option<u16> {
	let b: [u8; 8] = io.make_bytes(b"card");
	// We make one in half the draws invalid so nobody knows how many cards anyone else has
	// if b[7] & 0x80 { return None; }
	Some((u64::from_le_bytes(b) % (NUM_CARDS as u64)) as u16)
}

/// Attempts to draw a card
fn try_draw(keypair: &Keypair, seed: &[u8; 32], draw_num: u8) -> Option<(u16, [u8; 97])> {
	let t = draw_transcript(seed, draw_num)?;
	let (io, proof, _) = keypair.vrf_sign(t);
	let card = find_card(&io)?;
	let mut vrf_signature = [0u8; 97];
	// the first 32 bytes are io
	vrf_signature[..32].copy_from_slice(&io.to_preout().to_bytes()[..]);
	// the next 64 bytes are the proof
	vrf_signature[32..96].copy_from_slice(&proof.to_bytes()[..]);
	// the final byte is the draw number
	vrf_signature[96] = draw_num;
	Some((card, vrf_signature))
}

/// Draws all our cards for the give seed
fn draws(keypair: &Keypair, seed: &[u8; 32]) -> Vec<(u16, [u8; 97])> {
	(0..NUM_DRAWS).filter_map(|i| try_draw(keypair, seed, i)).collect()
}

/// Verifies a card play
///
/// We depend upon application code to enforce the public key and seed
/// being chosen correctly.
///
/// We encode the draw number into the vrf signature since an honest
/// application has no use for this, outside the verification check in
/// `draw_transcript`.
fn recieve(public: &PublicKey, vrf_signature: &[u8; 97], seed: &[u8; 32]) -> Option<u16> {
	let t = draw_transcript(seed, vrf_signature[96])?;
	let out = VRFPreOut::from_bytes(&vrf_signature[..32]).ok()?;
	let proof = VRFProof::from_bytes(&vrf_signature[32..96]).ok()?;
	// We need not understand the error type here, but someone might
	// care about invalid signatures vs invalid card draws.
	let (io, _) = public.vrf_verify(t, &out, &proof).ok()?;
	find_card(&io)
}
