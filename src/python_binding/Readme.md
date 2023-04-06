# L15 python module

## Importing example

```python
import sys
sys.path.append("...path/to/module/directory...")
import libl15_core_pybind as l15

print(l15.Version())
```

# Module libl15_core_pybind

## `CreateInscriptionBuilder(chain_mode: str) -> libl15_core_pybind.CreateInscriptionBuilder`  
Creates instance of `CreateInscriptionBuilder` class  
*Parameters:*  
 - `chain_mode: str` - is a mode of blockchain. Must be one of the following values: `mainnet`, `testnet`, `regtest`, otherwise will raise an exception      

## Class `CreateInscriptionBuilder`
This class is responsible for creation of an inscription  

### `GetProtocolVersion() -> int`
Returns protocol version. This field is required for further enhancements

### `GetUtxoTxId() -> str`
Accessor for UTXO identifier

### `SetUtxoTxId(v: str)`  
Sets UTXO identifier for the inscription to be built  

*Parameters:*  
 - `v: str` - is a UTXO identifier  

### `GetUtxoNOut() -> int`
Accessor for previously set UTXO transaction output number 

### `SetUtxoNOut(v: int)`
Sets UTXO transaction output number for the inscription

*Parameters:*  
 - `v: int` - is an UTXO output number

### `GetUtxoAmount() -> str`
Returns amount of bitcoin previously set for the inscription. Looks like a price of inscription

### `SetUtxoAmount(v: str)`
Sets amount of bitcoin for the inscription. Looks like a price of inscription

*Parameters:*  
 - `v: str` - is an amount in bitcoins

### `GetContentType() -> str`
Returns content type previously set for theinscription

### `SetContentType(v: str)`
Sets content type for the inscription

*Parameters:*  
 - `v: str` - is a content type

### `GetContent() -> str`
Returns hex representation of content previously set for the inscription

### `SetContent(v: str)`
Sets content for inscription

*Parameters:*  
 - `v: str` - is a hex-encoded content

### `GetDestinationPubKey() -> str`
Returns hex representation of destination public key previously set for the inscription  

### `SetDestinationPubKey(v: str)`
Sets destination public key for the inscription  

*Parameters:*  
 - `v: str` - is a hex-encoded destination public key  

### `GetIntermediateSecKey(v: str) -> str`
std::string GetIntermediateSecKey() const { return l15::hex(m_inscribe_taproot_sk.value()); }

### `UTXO(txid: str, nout: int, amount: str) -> CreateInscriptionBuilder`
This is a convenience method which sets three parameters of inscription simultaneously

*Parameters:*  
- `txid: str` - is a UTXO identifier  
- `nout: int` - is a UTXO output number  
- `amount: str` - is an amount in bitcoins  

*Returns:*   
    Reference to itself, which allows to chain method calls

### `Data(content_type: str, hex_data: str) -> CreateInscriptionBuilder`
This is a convenience method which parameters of inscription content

*Parameters:*  
- `content_type: str` - is a content type  
- `hex_data: str` - is a hex-encoded content   

*Returns:*   
Reference to itself, which allows to chain method calls

### `FeeRate(rate: str) -> CreateInscriptionBuilder`
Sets fee rate for inscription transactions

*Parameters:*
- `rate: str` - is a fee rate

*Returns:*   
Reference to itself, which allows to chain method calls

### `Destination(pk: str) -> CreateInscriptionBuilder`
Sets inscription destination public key

*Parameters:*
- `pk: str` - is a destination public key

*Returns:*   
Reference to itself, which allows to chain method calls

### `IntermediateTaprootPrivKey() -> str`
Returns taproot private key
Needed in case of a fallback scenario to return funds

### `GetUtxoPubKey() -> str`
Returns hex-encoded UTXO public key

### `GetUtxoSig() -> str`
Returns hex-encoded UTXO signature key

### `GetInscribeScriptPubKey() -> str`
Returns hex-encoded inscription script public key

### `GetInscribeScriptSig() -> str`
Returns hex-encoded inscription script signature

### `GetInscribeInternaltPubKey() -> str`
Returns hex-encoded inscription internal public key

### `Sign(utxo_sk: str)`
Checks arguments set for the inscription. Creates funding and genesis transactions

### `std::vector<std::string> RawTransactions() -> List[str]`
Returns funding and genesis transactions

### `Serialize()  -> str`
Returns JSON-serialized inscription creation data

### `Deserialize(data: str)`
Parses JSON-serialized inscription creation data, sets it to the builder and recreates transactions

*Parameters:*  
- `data: str` - is a JSON data
 
## Examples

### C++ Example
```c++
ChannelKeys utxo_key(w->wallet().Secp256k1Context());
ChannelKeys dest_key(w->wallet().Secp256k1Context());

//create address from key pair
string addr = w->btc().Bech32Encode(utxo_key.GetLocalPubKey());

//send to the address
string txid = w->btc().SendToAddress(addr, "1");

auto prevout = w->btc().CheckOutput(txid, addr);

std::string fee_rate = "0.00005";

//CHECK_NOTHROW(fee_rate = w->btc().EstimateSmartFee("1"));

std::clog << "Fee rate: " << fee_rate << std::endl;

CreateInscriptionBuilder builder("regtest");

builder.SetUtxoTxId(get<0>(prevout).hash.GetHex());
builder.SetUtxoNOut(get<0>(prevout).n);
builder.SetUtxoAmount("1");
builder.SetMiningFeeRate(fee_rate);
builder.SetContentType("text");
builder.SetContent(hex(std::string("test")));
builder.SetDestinationPubKey(hex(dest_key.GetLocalPubKey()));
builder.Sign(hex(utxo_key.GetLocalPrivKey()))

std::string ser_data;
ser_data = builder.Serialize();

std::clog << ser_data << std::endl;

CreateInscriptionBuilder builder2("regtest");

builder2.Deserialize(ser_data);

stringvector rawtx;
rawtx = builder2.RawTransactions();

CMutableTransaction funding_tx, genesis_tx;
DecodeHexTx(funding_tx, rawtx.front());
DecodeHexTx(genesis_tx, rawtx.back());

w->btc().SpendTx(CTransaction(funding_tx));
w->btc().SpendTx(CTransaction(genesis_tx));
```

### Python example
```python
import sys
from binascii import hexlify

sys.path.append("...path/to/module/directory...")

import libl15_core_pybind as l15

try:
    builder = l15.CreateInscriptionBuilder("regtest")

    builder.UTXO("abcdefgh", 1, "1").\
        Data("text", hexlify("content".encode()).decode()).\
        FeeRate("0.00005").\
        Sign("34234234")

    data = builder.Serialize()
except Exception as e:
    print("Exception: ", e.args[0])
```