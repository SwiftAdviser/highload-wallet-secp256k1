import {compile, NetworkProvider} from '@ton/blueprint';
import { toNano } from '@ton/ton';
import { wordlist } from 'ethereum-cryptography/bip39/wordlists/english';
import { HDKey } from 'ethereum-cryptography/hdkey';
import * as bip39 from 'ethereum-cryptography/bip39';
import { secp256k1 as secp } from 'ethereum-cryptography/secp256k1';
import { HighloadWalletV3 } from '../wrappers/HighloadWalletV3';

export async function run(provider: NetworkProvider) {
    let privateKey: Uint8Array;

    if(process.env.HIGHLOAD_WALLET_MNEMONIC) {
        const mnemonic = process.env.HIGHLOAD_WALLET_MNEMONIC;
        if(!bip39.validateMnemonic(mnemonic, wordlist)) {
            throw RangeError("Mnemonic doesn't belong to BEP-39 wordlist");
        }
        const seed = await bip39.mnemonicToSeed(mnemonic);
        const masterKey = HDKey.fromMasterSeed(seed);
        if(masterKey.privateKey === null) {
            throw Error("Failed to generate private key from mnemonic!");
        }

        privateKey = masterKey.privateKey;
    } else if(process.env.HIGHLOAD_WALLET_KEY) {
        const keyBuff = Buffer.from(process.env.HIGHLOAD_WALLET_KEY, 'hex');
        privateKey = Uint8Array.from(keyBuff);

        if(!secp.utils.isValidPrivateKey(privateKey)) {
            console.log("Expected 33 byte hex string");
            throw Error("Not valid key in HIGHLOAD_WALLET_KEY variable");
        }
    } else {
        throw Error("HIGHLOAD_WALLET_MNEMONIC or HIGHLOAD_WALLET_KEY env variable is required!");
    }

    const highloadCode = await compile('HighloadWalletV3');
    const publicKey    = secp.getPublicKey(privateKey);

    const highloadContract = provider.open(
        HighloadWalletV3.createFromConfig({
            publicKey,
            subwalletId: 0,
            timeout: 24 * 3600 * 30,
        }, highloadCode));

    await highloadContract.sendDeploy(provider.sender(), toNano('100'));
    await provider.waitForDeploy(highloadContract.address, 50);
}
