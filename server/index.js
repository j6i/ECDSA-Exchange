const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const SHA256 = require('crypto-js/sha256');
// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());


function genKeys(){
  const key = ec.genKeyPair();
// encode the entire public key as a hexadecimal string
  const pKey = key.getPublic().encode('hex');
  return {publicKey: pKey.toString(16), publicX: key.getPublic().x.toString(16), publicY: key.getPublic().y.toString(16), privateKey: key.getPrivate().toString(16)};
}

const acc1 = genKeys();
const acc2 = genKeys();
const acc3 = genKeys();

const balances = {
  [acc1.publicKey]: 100,
  [acc2.publicKey]: 100,
  [acc3.publicKey]: 100
}
console.log("Public Keys \n1. " + acc1.publicKey + "\n2. " + acc2.publicKey + "\n3. " + acc3.publicKey + "\n");
console.log("Private Keys \n1. " + acc1.privateKey + "\n2. " + acc2.privateKey + "\n3. " + acc3.privateKey + "\n");

function signTx(privKey){
  const key = ec.keyFromPrivate(privKey);
  // TODO: change this message to whatever you would like to sign
  const message = "I autherize this transaction";
  const msgHash = SHA256(message);
  const signature = key.sign(msgHash.toString());
  return {
      r: signature.r.toString(16),
      s: signature.s.toString(16)
  };
}

function grabAcc(sender){
  if (acc1.publicKey === sender){
    return acc1;
  }
  if (acc2.publicKey === sender){
    return acc2;
  }
  if (acc3.publicKey === sender){
    return acc3;
  }
}

function verifyTx(sender, privKey){
  const acc = grabAcc(sender);
  const pubKey = {
    x: acc.publicX,
    y: acc.publicY
  }
  const key = ec.keyFromPublic(pubKey, 'hex');
  const msg = "I autherize this transaction";
  const msgHash = SHA256(msg).toString();
  const signature = signTx(privKey);
  return key.verify(msgHash, signature);
}



app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, privKey, recipient, amount} = req.body;
  if (verifyTx(sender, privKey)){
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
    console.log("sent");
  }
  else {
    console.log("failed");
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
