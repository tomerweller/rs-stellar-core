//! Classic event emission for Stellar assets.

use stellar_core_common::NetworkId;
use stellar_core_crypto::PublicKey as StrKeyPublicKey;
use stellar_xdr::curr::{
    AccountId, Asset, ClaimableBalanceId, ContractEvent, ContractEventBody, ContractEventType,
    ContractEventV0, ContractId, ContractIdPreimage, Hash, HashIdPreimage,
    HashIdPreimageContractId, Int128Parts, Memo, MuxedAccount, MuxedEd25519Account,
    PublicKey as XdrPublicKey, ScAddress, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, StringM,
    TransactionEvent, TransactionEventStage,
};

#[derive(Debug, Clone, Copy)]
pub struct ClassicEventConfig {
    pub emit_classic_events: bool,
    pub backfill_stellar_asset_events: bool,
}

impl Default for ClassicEventConfig {
    fn default() -> Self {
        Self {
            emit_classic_events: false,
            backfill_stellar_asset_events: false,
        }
    }
}

impl ClassicEventConfig {
    pub fn events_enabled(self, protocol_version: u32) -> bool {
        if protocol_version >= 23 {
            self.emit_classic_events
        } else {
            self.backfill_stellar_asset_events
        }
    }

    pub fn backfill_to_protocol23(self, protocol_version: u32) -> bool {
        self.backfill_stellar_asset_events && protocol_version < 23
    }
}

pub struct OpEventManager {
    enabled: bool,
    backfill_to_protocol23: bool,
    events: Vec<ContractEvent>,
    network_id: NetworkId,
    memo: Memo,
}

impl OpEventManager {
    pub fn new(
        meta_enabled: bool,
        is_soroban: bool,
        protocol_version: u32,
        network_id: NetworkId,
        memo: Memo,
        config: ClassicEventConfig,
    ) -> Self {
        let enabled = meta_enabled && (is_soroban || config.events_enabled(protocol_version));
        let backfill_to_protocol23 = config.backfill_to_protocol23(protocol_version);
        Self {
            enabled,
            backfill_to_protocol23,
            events: Vec::new(),
            network_id,
            memo,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn events_for_claim_atoms(
        &mut self,
        source: &MuxedAccount,
        claim_atoms: &[stellar_xdr::curr::ClaimAtom],
    ) {
        if !self.enabled {
            return;
        }
        let source_addr = make_muxed_account_address(source);
        for atom in claim_atoms {
            match atom {
                stellar_xdr::curr::ClaimAtom::OrderBook(claim) => {
                    let seller = make_account_address(&claim.seller_id);
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_bought,
                        &source_addr,
                        &seller,
                        claim.amount_bought,
                        false,
                    );
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_sold,
                        &seller,
                        &source_addr,
                        claim.amount_sold,
                        false,
                    );
                }
                stellar_xdr::curr::ClaimAtom::LiquidityPool(claim) => {
                    let pool = ScAddress::LiquidityPool(claim.liquidity_pool_id.clone());
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_bought,
                        &source_addr,
                        &pool,
                        claim.amount_bought,
                        false,
                    );
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_sold,
                        &pool,
                        &source_addr,
                        claim.amount_sold,
                        false,
                    );
                }
                stellar_xdr::curr::ClaimAtom::V0(claim) => {
                    let seller = ScAddress::Account(AccountId::from(
                        XdrPublicKey::PublicKeyTypeEd25519(claim.seller_ed25519.clone()),
                    ));
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_bought,
                        &source_addr,
                        &seller,
                        claim.amount_bought,
                        false,
                    );
                    self.event_for_transfer_with_issuer_check(
                        &claim.asset_sold,
                        &seller,
                        &source_addr,
                        claim.amount_sold,
                        false,
                    );
                }
            }
        }
    }

    pub fn event_for_transfer_with_issuer_check(
        &mut self,
        asset: &Asset,
        from: &ScAddress,
        to: &ScAddress,
        amount: i64,
        allow_muxed_id_or_memo: bool,
    ) {
        if !self.enabled {
            return;
        }

        let from_is_issuer = is_issuer(from, asset);
        let to_is_issuer = is_issuer(to, asset);

        if from_is_issuer && to_is_issuer {
            self.new_transfer_event(asset, from, to, amount, allow_muxed_id_or_memo);
        } else if from_is_issuer {
            self.new_mint_event(asset, to, amount, allow_muxed_id_or_memo);
        } else if to_is_issuer {
            self.new_burn_event(asset, from, amount);
        } else {
            self.new_transfer_event(asset, from, to, amount, allow_muxed_id_or_memo);
        }
    }

    pub fn new_transfer_event(
        &mut self,
        asset: &Asset,
        from: &ScAddress,
        to: &ScAddress,
        amount: i64,
        allow_muxed_id_or_memo: bool,
    ) {
        if !self.enabled {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, asset);
        let topics = vec![
            make_symbol_scval("transfer"),
            ScVal::Address(get_address_with_dropped_muxed_info(from)),
            ScVal::Address(get_address_with_dropped_muxed_info(to)),
            make_sep0011_asset_string_scval(asset),
        ];
        let data = make_possible_muxed_data(to, amount, &self.memo, allow_muxed_id_or_memo);
        self.events.push(make_event(contract_id, topics, data));
    }

    pub fn new_mint_event(
        &mut self,
        asset: &Asset,
        to: &ScAddress,
        amount: i64,
        allow_muxed_id_or_memo: bool,
    ) {
        if !self.enabled {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, asset);
        let topics = vec![
            make_symbol_scval("mint"),
            ScVal::Address(get_address_with_dropped_muxed_info(to)),
            make_sep0011_asset_string_scval(asset),
        ];
        let data = make_possible_muxed_data(to, amount, &self.memo, allow_muxed_id_or_memo);
        self.events.push(make_event(contract_id, topics, data));
    }

    pub fn new_burn_event(&mut self, asset: &Asset, from: &ScAddress, amount: i64) {
        if !self.enabled {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, asset);
        let topics = vec![
            make_symbol_scval("burn"),
            ScVal::Address(get_address_with_dropped_muxed_info(from)),
            make_sep0011_asset_string_scval(asset),
        ];
        let data = make_i128_scval(amount);
        self.events.push(make_event(contract_id, topics, data));
    }

    pub fn new_clawback_event(&mut self, asset: &Asset, from: &ScAddress, amount: i64) {
        if !self.enabled {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, asset);
        let topics = vec![
            make_symbol_scval("clawback"),
            ScVal::Address(get_address_with_dropped_muxed_info(from)),
            make_sep0011_asset_string_scval(asset),
        ];
        let data = make_i128_scval(amount);
        self.events.push(make_event(contract_id, topics, data));
    }

    pub fn new_set_authorized_event(&mut self, asset: &Asset, account: &AccountId, authorize: bool) {
        if !self.enabled {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, asset);
        let topics = vec![
            make_symbol_scval("set_authorized"),
            ScVal::Address(ScAddress::Account(account.clone())),
            make_sep0011_asset_string_scval(asset),
        ];
        let data = ScVal::Bool(authorize);
        self.events.push(make_event(contract_id, topics, data));
    }

    pub fn set_events(&mut self, mut events: Vec<ContractEvent>) {
        if !self.enabled {
            return;
        }
        if !self.backfill_to_protocol23 {
            self.events = events;
            return;
        }

        for event in events.iter_mut() {
            let Some(asset) = get_asset_from_event(event, &self.network_id) else {
                continue;
            };

            let ContractEventBody::V0(body) = &mut event.body;
            let topics = body.topics.clone();
            if topics.is_empty() {
                continue;
            }
            let Some(name) = scval_symbol_bytes(&topics[0]) else {
                continue;
            };

            match name.as_slice() {
                b"transfer" => {
                    if topics.len() != 4 {
                        continue;
                    }
                    let from = match &topics[1] {
                        ScVal::Address(addr) => addr,
                        _ => continue,
                    };
                    let to = match &topics[2] {
                        ScVal::Address(addr) => addr,
                        _ => continue,
                    };
                    let from_is_issuer = is_issuer(from, &asset);
                    let to_is_issuer = is_issuer(to, &asset);
                    if (from_is_issuer && to_is_issuer) || (!from_is_issuer && !to_is_issuer) {
                        continue;
                    }
                    let mut topics_vec: Vec<ScVal> =
                        topics.iter().cloned().collect();
                    if from_is_issuer {
                        topics_vec[0] = make_symbol_scval("mint");
                        topics_vec.remove(1);
                    } else {
                        topics_vec[0] = make_symbol_scval("burn");
                        topics_vec.remove(2);
                    }
                    body.topics = topics_vec.try_into().unwrap_or_default();
                }
                b"mint" | b"clawback" | b"set_authorized" => {
                    if topics.len() == 4 {
                        let mut topics_vec: Vec<ScVal> =
                            topics.iter().cloned().collect();
                        topics_vec.remove(1);
                        body.topics = topics_vec.try_into().unwrap_or_default();
                    }
                }
                _ => {}
            }
        }

        self.events = events;
    }

    pub fn finalize(self) -> Vec<ContractEvent> {
        self.events
    }
}

pub struct TxEventManager {
    enabled: bool,
    events: Vec<TransactionEvent>,
    network_id: NetworkId,
}

impl TxEventManager {
    pub fn new(meta_enabled: bool, protocol_version: u32, network_id: NetworkId, config: ClassicEventConfig) -> Self {
        let enabled = meta_enabled && config.events_enabled(protocol_version);
        Self {
            enabled,
            events: Vec::new(),
            network_id,
        }
    }

    pub fn new_fee_event(&mut self, fee_source: &AccountId, amount: i64, stage: TransactionEventStage) {
        if !self.enabled || amount == 0 {
            return;
        }
        let contract_id = get_asset_contract_id(&self.network_id, &Asset::Native);
        let topics = vec![
            make_symbol_scval("fee"),
            ScVal::Address(ScAddress::Account(fee_source.clone())),
        ];
        let data = make_i128_scval(amount);
        let event = make_event(contract_id, topics, data);
        self.events.push(TransactionEvent { stage, event });
    }

    pub fn finalize(self) -> Vec<TransactionEvent> {
        self.events
    }
}

pub fn make_muxed_account_address(muxed: &MuxedAccount) -> ScAddress {
    match muxed {
        MuxedAccount::Ed25519(pk) => ScAddress::Account(AccountId::from(
            XdrPublicKey::PublicKeyTypeEd25519(pk.clone()),
        )),
        MuxedAccount::MuxedEd25519(m) => ScAddress::MuxedAccount(MuxedEd25519Account {
            id: m.id,
            ed25519: m.ed25519.clone(),
        }),
    }
}

pub fn make_account_address(account: &AccountId) -> ScAddress {
    ScAddress::Account(account.clone())
}

pub fn make_claimable_balance_address(balance_id: &ClaimableBalanceId) -> ScAddress {
    ScAddress::ClaimableBalance(balance_id.clone())
}

fn make_event(contract_id: ContractId, topics: Vec<ScVal>, data: ScVal) -> ContractEvent {
    let topics: Vec<ScVal> = topics;
    ContractEvent {
        ext: stellar_xdr::curr::ExtensionPoint::V0,
        contract_id: Some(contract_id),
        type_: ContractEventType::Contract,
        body: ContractEventBody::V0(ContractEventV0 {
            topics: topics.try_into().unwrap_or_default(),
            data,
        }),
    }
}

fn get_address_with_dropped_muxed_info(address: &ScAddress) -> ScAddress {
    match address {
        ScAddress::MuxedAccount(muxed) => ScAddress::Account(AccountId::from(
            XdrPublicKey::PublicKeyTypeEd25519(muxed.ed25519.clone()),
        )),
        _ => address.clone(),
    }
}

fn make_sep0011_asset_string_scval(asset: &Asset) -> ScVal {
    let asset_str = match asset {
        Asset::Native => "native".to_string(),
        Asset::CreditAlphanum4(a) => format!(
            "{}:{}",
            asset_code_to_string(&a.asset_code.0),
            account_id_to_strkey(&a.issuer).unwrap_or_default()
        ),
        Asset::CreditAlphanum12(a) => format!(
            "{}:{}",
            asset_code_to_string(&a.asset_code.0),
            account_id_to_strkey(&a.issuer).unwrap_or_default()
        ),
    };
    ScVal::String(ScString(StringM::try_from(asset_str).unwrap_or_default()))
}

fn account_id_to_strkey(account_id: &AccountId) -> Option<String> {
    let public_key = match account_id {
        AccountId(pk) => StrKeyPublicKey::try_from(pk).ok()?,
    };
    Some(public_key.to_strkey())
}

fn asset_code_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn make_symbol_scval(value: &str) -> ScVal {
    let sym = ScSymbol(StringM::try_from(value).unwrap_or_default());
    ScVal::Symbol(sym)
}

fn make_string_scval(value: &str) -> ScVal {
    ScVal::String(ScString(StringM::try_from(value).unwrap_or_default()))
}

fn make_i128_scval(amount: i64) -> ScVal {
    let value = amount as i128;
    ScVal::I128(Int128Parts {
        hi: (value >> 64) as i64,
        lo: value as u64,
    })
}

fn make_u64_scval(value: u64) -> ScVal {
    ScVal::U64(value)
}

fn make_bytes_scval(bytes: &[u8]) -> ScVal {
    ScVal::Bytes(bytes.to_vec().try_into().unwrap_or_default())
}

fn make_classic_memo_scval(memo: &Memo) -> ScVal {
    match memo {
        Memo::None => panic!("memo type cannot be None for classic memo encoding"),
        Memo::Text(text) => {
            let value = std::str::from_utf8(text.as_ref()).unwrap_or("");
            make_string_scval(value)
        }
        Memo::Id(id) => make_u64_scval(*id),
        Memo::Hash(hash) => make_bytes_scval(&hash.0),
        Memo::Return(ret) => make_bytes_scval(&ret.0),
    }
}

fn make_possible_muxed_data(
    to: &ScAddress,
    amount: i64,
    memo: &Memo,
    allow_muxed_id_or_memo: bool,
) -> ScVal {
    let is_to_muxed = matches!(to, ScAddress::MuxedAccount(_));
    let has_memo = !matches!(memo, Memo::None);

    if !allow_muxed_id_or_memo || (!is_to_muxed && !has_memo) {
        return make_i128_scval(amount);
    }

    let mut map = Vec::new();
    map.push(ScMapEntry {
        key: make_symbol_scval("amount"),
        val: make_i128_scval(amount),
    });
    let muxed_val = if let ScAddress::MuxedAccount(muxed) = to {
        make_u64_scval(muxed.id)
    } else {
        make_classic_memo_scval(memo)
    };
    map.push(ScMapEntry {
        key: make_symbol_scval("to_muxed_id"),
        val: muxed_val,
    });
    ScVal::Map(Some(ScMap(map.try_into().unwrap_or_default())))
}

fn is_issuer(address: &ScAddress, asset: &Asset) -> bool {
    let account = match address {
        ScAddress::Account(account) => account,
        _ => return false,
    };
    match asset {
        Asset::Native => false,
        Asset::CreditAlphanum4(a) => &a.issuer == account,
        Asset::CreditAlphanum12(a) => &a.issuer == account,
    }
}

fn get_asset_contract_id(network_id: &NetworkId, asset: &Asset) -> ContractId {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash::from(network_id.0),
        contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
    });
    let hash = stellar_core_common::Hash256::hash_xdr(&preimage)
        .unwrap_or_else(|_| stellar_core_common::Hash256::ZERO);
    ContractId(Hash::from(hash))
}

fn scval_symbol_bytes(value: &ScVal) -> Option<Vec<u8>> {
    match value {
        ScVal::Symbol(sym) => {
            let bytes: &[u8] = sym.0.as_ref();
            Some(bytes.to_vec())
        }
        _ => None,
    }
}

fn get_asset_from_event(event: &ContractEvent, network_id: &NetworkId) -> Option<Asset> {
    let contract_id = event.contract_id.as_ref()?;
    let ContractEventBody::V0(body) = &event.body;
    let asset_val = body.topics.last()?;
    let asset_str = match asset_val {
        ScVal::String(s) => std::str::from_utf8(s.0.as_ref()).ok()?,
        _ => return None,
    };

    let asset = if asset_str == "native" {
        Asset::Native
    } else if let Some((code, issuer_str)) = asset_str.split_once(':') {
        let issuer_pk = StrKeyPublicKey::from_strkey(issuer_str).ok()?;
        let issuer = AccountId::from(XdrPublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(*issuer_pk.as_bytes()),
        ));
        let code_bytes = code.as_bytes();
        if code_bytes.len() <= 4 {
            let mut buf = [0u8; 4];
            buf[..code_bytes.len()].copy_from_slice(code_bytes);
            Asset::CreditAlphanum4(stellar_xdr::curr::AlphaNum4 {
                asset_code: stellar_xdr::curr::AssetCode4(buf),
                issuer,
            })
        } else if code_bytes.len() <= 12 {
            let mut buf = [0u8; 12];
            buf[..code_bytes.len()].copy_from_slice(code_bytes);
            Asset::CreditAlphanum12(stellar_xdr::curr::AlphaNum12 {
                asset_code: stellar_xdr::curr::AssetCode12(buf),
                issuer,
            })
        } else {
            return None;
        }
    } else {
        return None;
    };

    let expected = get_asset_contract_id(network_id, &asset);
    if &expected != contract_id {
        return None;
    }
    Some(asset)
}
