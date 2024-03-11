### RunReturn object

```
dictionary Msg {
    string? message;
    u8? type;
    string? uuid;
    string? index;
    string? sender;
    u64? msat;
    u64? timestamp;
    string? sent_to;
};
```

```
dictionary RunReturn {
    sequence<Msg> msgs;
    sequence<string> topics;
    sequence<bytes> payloads;
    bytes? state_mp;
    sequence<string> state_to_delete;
    u64? new_balance;
    string? my_contact_info;
    string? sent_status;
    string? settled_status;
    string? error;
    string? new_tribe;
    string? tribe_members;
    string? new_invite;
    string? inviter_contact_info;
    string? inviter_alias;
    string? initial_tribe;
    string? lsp_host;
    string? invoice;
    string? route;
    string? node;
    string? last_read;
    string? mute_levels;
};
```

### functions

string `pubkey_from_secret_key(string my_secret_key)`

string `mnemonic_from_entropy(string entropy)`

string `entropy_from_mnemonic(string mnemonic)`

string `mnemonic_to_seed(string mnemonic)`

string `entropy_to_seed(string entropy)`

string `make_auth_token(u32 ts, string secret)`

string `sign_ms(string seed, u64 idx, string time, string network)`

string `sign_bytes(string seed, u64 idx, string time, string network, bytes msg)`

string `pubkey_from_seed(string seed, u64 idx, string time, string network)`

string `root_sign_ms(string seed, string time, string network)`

string `xpub_from_seed(string seed, string time, string network)`

RunReturn `set_network(string network)`

RunReturn `set_blockheight(u32 blockheight)`

RunReturn `add_contact(string seed, string unique_time, bytes state, string to_pubkey, string route_hint, string my_alias, string my_img, u64 amt_msat, string? invite_code)`

string `get_contact(bytes state, string pubkey)`

string `list_contacts(bytes state)`

string `get_subscription_topic(string seed, string unique_time, bytes state)`

string `get_tribe_management_topic(string seed, string unique_time, bytes state)`

RunReturn `initial_setup(string seed, string unique_time, bytes state)`

RunReturn `fetch_msgs(string seed, string unique_time, bytes state, u64 last_msg_idx, u32? limit)`

RunReturn `handle(string topic, bytes payload, string seed, string unique_time, bytes state, string my_alias, string my_img)`

RunReturn `send(string seed, string unique_time, string to, u8 msg_type, string msg_json, bytes state, string my_alias, string my_img, u64 amt_msat, optional boolean is_tribe = false)`

string `make_media_token(string seed, string unique_time, bytes state, string host, string muid, string to, u32 expiry)`

string `make_media_token_with_meta(string seed, string unique_time, bytes state, string host, string muid, string to, u32 expiry, string meta)`

string `make_media_token_with_price(string seed, string unique_time, bytes state, string host, string muid, string to, u32 expiry, u64 price)`

RunReturn `make_invoice(string seed, string unique_time, bytes state, u64 amt_msat, string description)`

RunReturn `pay_invoice(string seed, string unique_time, bytes state, string bolt11, u64? overpay_msat)`

string `payment_hash_from_invoice(string bolt11)`

RunReturn `create_tribe(string seed, string unique_time, bytes state, string tribe_server_pubkey, string tribe_json)`

RunReturn `join_tribe(string seed, string unique_time, bytes state, string tribe_pubkey, string tribe_route_hint, string alias, u64 amt_msat, boolean is_private)`

RunReturn `list_tribe_members(string seed, string unique_time, bytes state, string tribe_server_pubkey, string tribe_pubkey)`

RunReturn `make_invite(string seed, string unique_time, bytes state, string host, u64 amt_msat, string my_alias, string? tribe_host, string? tribe_pubkey)`

RunReturn `process_invite(string seed, string unique_time, bytes state, string invite_qr)`

string `code_from_invite(string invite_qr)`

string `get_default_tribe_server(bytes state)`

RunReturn `read(string seed, string unique_time, bytes state, string pubkey, u64 msg_idx)`

RunReturn `get_reads(string seed, string unique_time, bytes state)`

RunReturn `mute(string seed, string unique_time, bytes state, string pubkey, u8 mute_level)`

RunReturn `get_mutes(string seed, string unique_time, bytes state)`
