use crate::vls_protocol;
use serde::ser;
use vls_protocol::msgs::{self, DeBolt, Message, SerBolt};
use vls_protocol_signer::lightning_signer::io::Cursor;

pub fn raw_request_from_bytes(
    message: Vec<u8>,
    sequence: u16,
    peer_id: [u8; 33],
    dbid: u64,
) -> vls_protocol::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let srh = msgs::SerialRequestHeader {
        sequence,
        peer_id,
        dbid,
    };
    msgs::write_serial_request_header(&mut &mut buf, &srh)?;
    msgs::write_vec(&mut &mut buf, message)?;
    Ok(buf)
}

pub fn request_from_msg<T: SerBolt + DeBolt>(
    msg: T,
    sequence: u16,
    peer_id: [u8; 33],
    dbid: u64,
) -> vls_protocol::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let srh = msgs::SerialRequestHeader {
        sequence,
        peer_id,
        dbid,
    };
    msgs::write_serial_request_header(&mut &mut buf, &srh)?;
    msgs::write(&mut &mut buf, msg)?;
    Ok(buf)
}

pub fn raw_response_from_msg<T: ser::Serialize + DeBolt>(
    msg: T,
    sequence: u16,
) -> vls_protocol::Result<Vec<u8>> {
    let mut buf = Vec::new();
    msgs::write_serial_response_header(&mut &mut buf, sequence)?;
    msgs::write(&mut &mut buf, msg)?;
    Ok(buf)
}

pub fn request_from_bytes<T: DeBolt>(
    msg: Vec<u8>,
) -> vls_protocol::Result<(T, msgs::SerialRequestHeader)> {
    let mut cursor = Cursor::new(msg);
    let srh: msgs::SerialRequestHeader = msgs::read_serial_request_header(&mut cursor)?;
    let reply: T = msgs::read_message(&mut cursor)?;
    Ok((reply, srh))
}

pub fn raw_response_from_bytes(
    res: Vec<u8>,
    expected_sequence: u16,
) -> vls_protocol::Result<Vec<u8>> {
    let mut cursor = Cursor::new(res);
    msgs::read_serial_response_header(&mut cursor, expected_sequence)?;
    Ok(msgs::read_raw(&mut cursor)?)
}

pub fn response_from_bytes(res: Vec<u8>, expected_sequence: u16) -> vls_protocol::Result<Message> {
    let mut cursor = Cursor::new(res);
    msgs::read_serial_response_header(&mut cursor, expected_sequence)?;
    Ok(msgs::read(&mut cursor)?)
}

#[cfg(test)]
mod tests {
    use vls_protocol::msgs;
    use vls_protocol::serde_bolt::WireString;

    // cargo test parser::tests::test_parser -- --exact
    #[test]
    fn test_parser() {
        let msg = "hello";
        let ping = msgs::Ping {
            id: 0,
            message: WireString(msg.as_bytes().to_vec()),
        };
        let mut buf = Vec::new();
        let srh = msgs::SerialRequestHeader {
            sequence: 0,
            peer_id: [0u8; 33],
            dbid: 0,
        };
        msgs::write_serial_request_header(&mut &mut buf, &srh)
            .expect("failed to write_serial_request_header");
        msgs::write(&mut &mut buf, ping).expect("failed to serial write");
        let _srh2 = msgs::read_serial_request_header(&mut buf).expect("read ping header");
        println!("{:?}", _srh2);
        let parsed_ping: msgs::Ping =
            msgs::read_message(&mut buf).expect("failed to read ping message");
        assert_eq!(parsed_ping.id, 0);
        assert_eq!(
            String::from_utf8(parsed_ping.message.0).unwrap(),
            msg.to_string()
        );
    }
}
