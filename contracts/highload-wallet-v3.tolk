import "@stdlib/tvm-dicts"
import "@stdlib/gas-payments"


/// Store binary true b{1} into `builder` [b]
@pure
fun storeTrue(b: builder): builder
    asm "STONE";
/// Stores [x] binary zeroes into `builder` [b].
@pure
fun storeZeroes(b: builder, x: int): builder
    asm "STZEROES";
/// Store `cell` [actions] to register c5 (out actions)
fun setActions(actions: cell): void
    asm "c5 POP";

const `op::internal_transfer` = 0xae42e5a4;

const `error::invalid_signature` = 33;
const `error::invalid_subwallet_id` = 34;
const `error::invalid_created_at` = 35;
const `error::already_executed` = 36;
const `error::invalid_message_to_send` = 37;
const `error::invalid_timeout` = 38;

const MSG_OP_SIZE = 32;
const MSG_QUERY_ID_SIZE = 64;

const KEY_SIZE = 13;
const SIGNATURE_SIZE = 512;
const PUBLIC_KEY_SIZE = 256;
const SUBWALLET_ID_SIZE = 32;
const TIMESTAMP_SIZE = 64;
const TIMEOUT_SIZE = 22; // 2^22 / 60 / 60 / 24 - up to ~48 days

const CELL_BITS_SIZE = 1023;
const BIT_NUMBER_SIZE = 10; // 2^10 = 1024

fun onInternalMessage(inMsgFull: cell, inMsgBody: slice) {
    var (bodyBits: int, bodyRefs: int) = inMsgBody.getRemainingBitsAndRefsCount();
    if (!((bodyRefs == 1) && (bodyBits == MSG_OP_SIZE + MSG_QUERY_ID_SIZE))) {
        return; // just accept TONs
    }

    var inMsgFullSlice: slice = inMsgFull.beginParse();
    var msgFlags: int = inMsgFullSlice.loadMessageFlags();
    if (msgFlags & 1) { // is bounced
        return;
    }

    var senderAddress: slice = inMsgFullSlice.loadAddress();

    // not from myself
    if (! senderAddress.isSliceBitsEqual(getMyAddress())) {
        return;  // just accept TONs
    }

    var op: int = inMsgBody.loadMessageOp();

    if (op == `op::internal_transfer`) {
        inMsgBody.skipMessageQueryId();
        var actions: cell = inMsgBody.preloadRef();
        var oldCode: cell = getContractCode();
        setActions(actions);
        setContractCodePostponed(oldCode); // prevent to change smart contract code
        return;
    }
}

fun onExternalMessage(msgBody: slice) {
    var msgInner: cell = msgBody.loadRef();
    var signature: slice = msgBody.loadBits(SIGNATURE_SIZE);
    msgBody.assertEndOfSlice();
    var msgInnerHash: int = msgInner.cellHash();

    var dataSlice: slice = getContractData().beginParse();
    var publicKey: int = dataSlice.loadUint(PUBLIC_KEY_SIZE);
    var subwalletId: int = dataSlice.loadUint(SUBWALLET_ID_SIZE);
    var oldQueries: cell? = dataSlice.loadDict();
    var queries: cell? = dataSlice.loadDict();
    var lastCleanTime: int = dataSlice.loadUint(TIMESTAMP_SIZE);
    var timeout: int = dataSlice.loadUint(TIMEOUT_SIZE);
    dataSlice.assertEndOfSlice();

    if (lastCleanTime < (now() - timeout)) {
        (oldQueries, queries) = (queries, null);
        if (lastCleanTime < (now() - (timeout * 2))) {
            oldQueries = null;
        }
        lastCleanTime = now();
    }

    assert(isSignatureValid(msgInnerHash, signature, publicKey)) throw `error::invalid_signature`;

    var msgInnerSlice: slice = msgInner.beginParse();
    var SubwalletId: int = msgInnerSlice.loadUint(SUBWALLET_ID_SIZE);
    var messageToSend: cell = msgInnerSlice.loadRef();
    var sendMode: int = msgInnerSlice.loadUint(8);
    var shift: int = msgInnerSlice.loadUint(KEY_SIZE);
    var bitNumber: int = msgInnerSlice.loadUint(BIT_NUMBER_SIZE);
    var createdAt: int = msgInnerSlice.loadUint(TIMESTAMP_SIZE);
    var Timeout: int  = msgInnerSlice.loadUint(TIMEOUT_SIZE);
    msgInnerSlice.assertEndOfSlice();

    assert(SubwalletId == subwalletId) throw `error::invalid_subwallet_id`;
    assert(Timeout == timeout) throw `error::invalid_timeout`;

    assert(createdAt > now() - timeout) throw `error::invalid_created_at`;
    assert(createdAt <= now()) throw `error::invalid_created_at`;

    var (value: cell?, found: bool) = oldQueries.uDictGetRef(KEY_SIZE, shift);
    if (found) {
        var valueSlice: slice = value!.beginParse();
        valueSlice.skipBits(bitNumber);
        assert(!(valueSlice.preloadInt(1))) throw `error::already_executed`;
    }

    var (value redef, found redef) = queries.uDictGetRef(KEY_SIZE, shift);
    var newValue: builder? = null;
    if (found) {
        var valueSlice: slice = value!.beginParse();
        var head: slice = valueSlice.loadBits(bitNumber);
        assert(!(valueSlice.loadInt(1))) throw `error::already_executed`;
        newValue = beginCell().storeSlice(head).storeTrue().storeSlice(valueSlice);
    } else {
        newValue = beginCell().storeZeroes(bitNumber).storeTrue().storeZeroes(CELL_BITS_SIZE - bitNumber - 1);
    }

    acceptExternalMessage();

    queries.uDictSetRef(KEY_SIZE, shift, newValue.endCell());

    setContractData(beginCell()
        .storeUint(publicKey, PUBLIC_KEY_SIZE)
        .storeUint(subwalletId, SUBWALLET_ID_SIZE)
        .storeDict(oldQueries)
        .storeDict(queries)
        .storeUint(lastCleanTime, TIMESTAMP_SIZE)
        .storeUint(timeout, TIMEOUT_SIZE)
        .endCell());


    commitContractDataAndActions();

    // after commit, check the message to prevent an error in the action phase

    var messageSlice: slice = messageToSend.beginParse();
    /*
       https://github.com/ton-blockchain/ton/blob/8a9ff339927b22b72819c5125428b70c406da631/crypto/block/block.tlb#L123C1-L124C33
       currencies$_ grams:Grams other:ExtraCurrencyCollection = CurrencyCollection;
       extra_currencies$_ dict:(HashmapE 32 (VarUInteger 32)) = ExtraCurrencyCollection;

       https://github.com/ton-blockchain/ton/blob/8a9ff339927b22b72819c5125428b70c406da631/crypto/block/block.tlb#L135
       int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
       src:MsgAddress dest:MsgAddressInt
       value:CurrencyCollection ihr_fee:Grams fwd_fee:Grams
       created_lt:uint64 created_at:uint32 = CommonMsgInfoRelaxed;

      https://github.com/ton-blockchain/ton/blob/8a9ff339927b22b72819c5125428b70c406da631/crypto/block/block.tlb#L155
      message$_ {X:Type} info:CommonMsgInfoRelaxed
      init:(Maybe (Either StateInit ^StateInit))
      body:(Either X ^X) = MessageRelaxed X;
    */

    assert(!(messageSlice.loadUint(1))) throw `error::invalid_message_to_send`; // int_msg_info$0
    var msgFlags: int = messageSlice.loadUint(3); // ihr_disabled:Bool bounce:Bool bounced:Bool
    if (msgFlags & 1) { // is bounced
        return;
    }
    var messageSourceAdrress: slice = messageSlice.loadAddress(); // src
    assert(addressIsNone(messageSourceAdrress)) throw `error::invalid_message_to_send`;
    messageSlice.loadAddress(); // dest
    messageSlice.loadCoins(); // value.coins
    messageSlice = messageSlice.skipDict(); // value.other extra-currencies
    messageSlice.loadCoins(); // ihr_fee
    messageSlice.loadCoins(); // fwd_fee
    messageSlice.skipBits(64 + 32); // created_lt:uint64 created_at:uint32
    var maybeStateInit: int = messageSlice.loadUint(1);
    assert(!(maybeStateInit)) throw `error::invalid_message_to_send`; // throw if state-init included (state-init not supported)
    var eitherBody: int = messageSlice.loadInt(1);
    if (eitherBody) {
        messageSlice.loadRef();
        messageSlice.assertEndOfSlice();
    }

    // send message with IGNORE_ERRORS flag to ignore errors in the action phase

    sendRawMessage(messageToSend, sendMode | SEND_MODE_IGNORE_ERRORS);
}


get get_public_key(): int {
    return getContractData().beginParse().preloadUint(PUBLIC_KEY_SIZE);
}

get get_subwallet_id(): int {
    var dataSlice: slice = getContractData().beginParse();
    dataSlice.skipBits(PUBLIC_KEY_SIZE); // skip public_key
    return dataSlice.preloadUint(SUBWALLET_ID_SIZE);
}

get get_last_clean_time(): int {
    var dataSlice: slice = getContractData().beginParse();
    dataSlice.skipBits(PUBLIC_KEY_SIZE + SUBWALLET_ID_SIZE + 1 + 1); // skip: public_key, subwallet_id, old_queried, queries
    return dataSlice.preloadUint(TIMESTAMP_SIZE);
}

get get_timeout(): int {
    var dataSlice: slice = getContractData().beginParse();
    dataSlice.skipBits(PUBLIC_KEY_SIZE + SUBWALLET_ID_SIZE + 1 + 1 + TIMESTAMP_SIZE); // skip: public_key, subwallet_id, old_queried, queries, last_clean_time
    return dataSlice.preloadUint(TIMEOUT_SIZE);
}

get `processed?`(queryId: int, needClean: int): bool {
    var shift: int = queryId >> BIT_NUMBER_SIZE;
    var bitNumber: int = queryId & CELL_BITS_SIZE;

    var dataSlice: slice = getContractData().beginParse();
    dataSlice.skipBits(PUBLIC_KEY_SIZE + SUBWALLET_ID_SIZE); // skip: public_key, subwallet_id
    var oldQueries: cell? = dataSlice.loadDict();
    var queries: cell? = dataSlice.loadDict();
    var lastCleanTime: int = dataSlice.loadUint(TIMESTAMP_SIZE);
    var timeout: int = dataSlice.loadUint(TIMEOUT_SIZE);
    dataSlice.assertEndOfSlice();

    if (needClean) {
        if (lastCleanTime < (now() - timeout)) {
            (oldQueries, queries) = (queries, null);
            if (lastCleanTime < (now() - (timeout * 2))) {
                oldQueries = null;
            }
            lastCleanTime = now();
        }
    }

    var (value: cell?, found: bool) = oldQueries.uDictGetRef(KEY_SIZE, shift);
    if (found) {
        var valueSlice: slice = value!.beginParse();
        valueSlice.skipBits(bitNumber);
        if (valueSlice.preloadInt(1)) {
            return true;
        }
    }

    var (value redef, found redef) = queries.uDictGetRef(KEY_SIZE, shift);
    if (found) {
        var valueSlice: slice = value!.beginParse();
        valueSlice.skipBits(bitNumber);
        if (valueSlice.preloadInt(1)) {
            return true;
        }
    }

    return false;
}
