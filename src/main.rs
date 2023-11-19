use clap::Parser;
use std::net::UdpSocket;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    resolver: Option<String>,
}

fn main() {
    let args = Args::parse();
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    listen(udp_socket, &args.resolver);
}

fn listen(udp_socket: UdpSocket, addr: &Option<String>) {
    println!("addr: {:#?}", addr);
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                // let _received_data = String::from_utf8_lossy(&buf[0..size]);
                // println!("Received {} bytes from {}", size, source);

                let response: Message = match addr {
                    Some(addr) => {
                        println!("doing forwarding");
                        let incoming = Message::from_bytes(&buf[..size]);

                        let mut outgoing = incoming.clone();
                        outgoing.header.qr = true;
                        outgoing.header.rcode = if incoming.header.opcode == 0 { 0 } else { 4 };
                        println!("{}", incoming.questions.len());
                        for q in &incoming.questions {
                            let mut msg = Message::default();
                            msg.header.id = incoming.header.id;
                            msg.header.qr = incoming.header.qr;
                            msg.header.qdcount = 1;
                            msg.questions = vec![q.clone()];

                            println!("forwarding {:#?}", msg);
                            udp_socket
                                .send_to(&msg.to_bytes(), addr)
                                .expect("resolver receives forwarded msg");
                            let mut res_bytes = [0; 512];
                            let (size, _s) = udp_socket
                                .recv_from(&mut res_bytes)
                                .expect("resolver responds");
                            let m = Message::from_bytes(&res_bytes[..size]);
                            println!("got {:#?}", m);
                            outgoing.answers.push(m.answers[0].clone());
                            outgoing.header.ancount += 1;
                        }
                        outgoing
                    }
                    None => parse_data(&buf[..size]),
                };

                udp_socket
                    .send_to(&response.to_bytes(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn parse_data(data: &[u8]) -> Message {
    let message = Message::from_bytes(data);
    let mut response = Message::default();

    println!("id {:#?}", message.header.id);
    // println!("question section: {:#?}", message.questions);

    for q in &message.questions {
        response.answers.push(q.get_answer());
    }
    response.questions = message.questions;
    response.header = MessageHeader {
        qr: true,
        aa: false,
        tc: false,
        ra: false,
        z: 0,
        rcode: if message.header.opcode == 0 { 0 } else { 4 },
        qdcount: response.questions.len() as u16,
        ancount: response.answers.len() as u16,
        nscount: 0,
        arcount: 0,
        ..message.header
    };
    // assert_eq!(response.header.ancount, 1);
    response
}

#[repr(C)]
#[derive(Clone, Debug)]
struct Question {
    // A domain name, represented as a sequence of "labels"
    name: Vec<u8>,
    // 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.
    record_type: u16,
    // 2-byte int; usually set to 1 (full list here)
    class: u16,
}
impl Question {
    #[allow(dead_code)]
    fn from_domain_string(name: String, record_type: u16, class: u16) -> Self {
        let peices = name.split('.');

        let mut labels: Vec<u8> = Vec::new();
        for piece in peices {
            labels.push(piece.len() as u8);
            labels.extend(piece.bytes());
        }
        labels.push(0);

        Question {
            name: labels,
            record_type,
            class,
        }
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.name);
        bytes.extend(self.record_type.to_be_bytes());
        bytes.extend(self.class.to_be_bytes());
        bytes
    }

    fn get_answer(self: &Self) -> ResourceRecord {
        ResourceRecord {
            name: self.name.clone(),
            record_type: self.record_type,
            class: self.class,
            ttl: 10,
            length: 4,
            data: vec![8, 8, 8, 8],
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ResourceRecord {
    name: Vec<u8>,    // 	Label Sequence 	The domain name encoded as a sequence of labels.
    record_type: u16, //	2-byte Integer 	1 for an A record, 5 for a CNAME record etc., full list here
    class: u16,       // 2-byte Integer 	Usually set to 1 (full list here)
    ttl: u32, // (Time-To-Live) 	4-byte Integer 	The duration in seconds a record can be cached before requerying.
    length: u16, // (RDLENGTH) 	2-byte Integer 	Length of the RDATA field in bytes.
    data: Vec<u8>, // (RDATA) 	Variable 	Data specific to the record type.
}
impl ResourceRecord {
    fn to_bytes(self: &Self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.name);
        bytes.extend(self.record_type.to_be_bytes());
        bytes.extend(self.class.to_be_bytes());
        bytes.extend(self.ttl.to_be_bytes());
        bytes.extend(self.length.to_be_bytes());
        bytes.extend(&self.data);
        bytes
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Message {
    header: MessageHeader,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<u8>,
    additional: Vec<u8>,
}
impl Default for Message {
    fn default() -> Self {
        Message {
            header: MessageHeader::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}
impl Message {
    fn from_bytes(bytes: &[u8]) -> Self {
        let header = MessageHeader::from_bytes(
            bytes[..12]
                .try_into()
                .expect("expected 12 bytes for a header"),
        );

        // let mut questions = Question::parse_from_message_bytes(&mut bytes[12..].to_vec().as_mut());

        let mut questions: Vec<Question> = Vec::new();
        // parse question section
        // let mut rest = &bytes[12..];
        let mut index = 12;

        for _i in 0..header.qdcount {
            // new domain name
            let mut labels: Vec<u8> = Vec::new();
            loop {
                let offset_val = bytes[index];
                if offset_val >= 0b11000000 {
                    // read label from pointer
                    let pointer =
                        u16::from_be_bytes([bytes[index] & !(0b11000000), bytes[index + 1]]);
                    index = pointer as usize;
                } else if offset_val == 0 {
                    // push question
                    labels.push(0);
                    index += 1;
                    let record_type = u16::from_be_bytes(
                        bytes[index..index + 2]
                            .try_into()
                            .expect("enough bytes for record type"),
                    );
                    let class = u16::from_be_bytes(
                        bytes[index + 2..index + 4]
                            .try_into()
                            .expect("enough bytes for record class"),
                    );
                    index += 4;
                    questions.push(Question {
                        name: labels,
                        record_type,
                        class,
                    });
                    break;
                } else {
                    // read and append next label
                    labels.push(offset_val);
                    index += 1;
                    labels.extend(&bytes[index..index + offset_val as usize]);
                    index += offset_val as usize;
                }
            }
        }

        let mut answers: Vec<ResourceRecord> = Vec::new();
        for _i in 0..header.ancount {
            let mut labels: Vec<u8> = Vec::new();
            loop {
                let offset_val = bytes[index];
                if offset_val >= 0b11000000 {
                    // read label from pointer
                    let pointer =
                        u16::from_be_bytes([bytes[index] & !(0b11000000), bytes[index + 1]]);
                    index = pointer as usize;
                } else if offset_val == 0 {
                    // push answer
                    labels.push(0);
                    index += 1;
                    let record_type = u16::from_be_bytes(
                        bytes[index..index + 2]
                            .try_into()
                            .expect("enough bytes for record type"),
                    );
                    let class = u16::from_be_bytes(
                        bytes[index + 2..index + 4]
                            .try_into()
                            .expect("enough bytes for record class"),
                    );
                    index += 4;

                    let ttl = u32::from_be_bytes(
                        bytes[index..index + 4]
                            .try_into()
                            .expect("enough bytes for ttl"),
                    );
                    index += 4;
                    let length = u16::from_be_bytes(
                        bytes[index..index + 2]
                            .try_into()
                            .expect("enough bytes for length"),
                    );
                    index += 2;
                    let data = bytes[index..].to_vec();
                    answers.push(ResourceRecord {
                        name: labels,
                        record_type,
                        class,
                        ttl,
                        length,
                        data,
                    });
                    break;
                } else {
                    // read and append next label
                    labels.push(offset_val);
                    index += 1;
                    labels.extend(&bytes[index..index + offset_val as usize]);
                    index += offset_val as usize;
                }
            }
        }

        let authority = Vec::new();
        let additional = Vec::new();
        Message {
            header,
            questions,
            answers,
            authority,
            additional,
        }
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend(self.header.to_bytes());
        for q in &self.questions {
            buf.extend(q.to_bytes());
        }
        for a in &self.answers {
            buf.extend(a.to_bytes());
        }
        buf
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
struct MessageHeader {
    // Packet Identifier (ID) 	16 bits 	A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,
    // Query/Response Indicator (QR) 	1 bit 	1 for a reply packet, 0 for a question packet.
    qr: bool,
    // Operation Code (OPCODE) 	4 bits 	Specifies the kind of query in a message.
    opcode: u8,
    // Authoritative Answer (AA) 	1 bit 	1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    aa: bool,
    // Truncation (TC) 	1 bit 	1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    tc: bool,
    // Recursion Desired (RD) 	1 bit 	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    rd: bool,
    // Recursion Available (RA) 	1 bit 	Server sets this to 1 to indicate that recursion is available.
    ra: bool,
    // Reserved (Z) 	3 bits 	Used by DNSSEC queries. At inception, it was reserved for future use.
    z: u8,
    // Response Code (RCODE) 	4 bits 	Response code indicating the status of the response.
    rcode: u8,
    // Question Count (QDCOUNT) 	16 bits 	Number of questions in the Question section.
    qdcount: u16,
    // Answer Record Count (ANCOUNT) 	16 bits 	Number of records in the Answer section.
    ancount: u16,
    // Authority Record Count (NSCOUNT) 	16 bits 	Number of records in the Authority section.
    nscount: u16,
    // Additional Record Count (ARCOUNT) 	16 bits 	Number of records in the Additional section.
    arcount: u16,
}
impl Default for MessageHeader {
    fn default() -> Self {
        MessageHeader {
            id: 1234,
            qr: true,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}
impl MessageHeader {
    fn from_bytes(bytes: [u8; 12]) -> MessageHeader {
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let qr = (bytes[2] >> 7) == 1;
        let opcode = (bytes[2] << 1) >> 4;

        let aa = ((bytes[2] << 5) >> 7) == 1;
        let tc = ((bytes[2] << 6) >> 7) == 1;
        let rd = ((bytes[2] << 7) >> 7) == 1;

        let ra = (bytes[3] >> 7) == 1;
        let z = (bytes[3] << 1) >> 5;
        let rcode = (bytes[3] << 4) >> 4;

        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        MessageHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    fn to_bytes<'a>(self: &Self) -> [u8; 12] {
        let mut bytes: [u8; 12] = [0; 12];

        let id_bytes = self.id.to_be_bytes();
        for (byte, id_byte) in bytes.iter_mut().zip(id_bytes.iter()) {
            *byte = *id_byte
        }

        // byte @ index 2
        if self.qr {
            bytes[2] |= 0b1000_0000;
        }
        bytes[2] += self.opcode << 3;
        if self.aa {
            bytes[2] |= 0b0000_0100;
        }
        if self.tc {
            bytes[2] |= 0b0000_0010;
        }
        if self.rd {
            bytes[2] |= 0b0000_0001;
        }
        // byte @ index 3
        if self.ra {
            bytes[3] |= 0b1000_0000;
        }
        bytes[3] += self.z << 4;
        bytes[3] += self.rcode;

        let qd_bytes = self.qdcount.to_be_bytes();
        let an_bytes = self.ancount.to_be_bytes();
        let ns_bytes = self.nscount.to_be_bytes();
        let ar_bytes = self.arcount.to_be_bytes();
        for (byte, qd_byte) in bytes[4..].iter_mut().zip(qd_bytes.iter()) {
            *byte = *qd_byte
        }
        for (byte, an_byte) in bytes[6..].iter_mut().zip(an_bytes.iter()) {
            *byte = *an_byte
        }
        for (byte, ns_byte) in bytes[8..].iter_mut().zip(ns_bytes.iter()) {
            *byte = *ns_byte
        }
        for (byte, ar_byte) in bytes[10..].iter_mut().zip(ar_bytes.iter()) {
            *byte = *ar_byte
        }
        bytes
    }
}
