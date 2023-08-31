import { expect, use } from 'chai'
import { RabinDemo } from '../src/contracts/rabinDemo'
import { getDefaultSigner } from './utils/txHelper'
import chaiAsPromised from 'chai-as-promised'
import axios from 'axios'
import { bsv, toByteString, Utils } from 'scrypt-ts'
import { RabinVerifierWOC, RabinSig } from 'scrypt-ts-lib'
import { Rabin, RabinSignature } from 'rabinsig'
use(chaiAsPromised)

const witnessServer = 'https://witnessonchain.com/v1'

interface numberToByteStringOptions {
    endian?: string; // big / little
    length?: number;
  }

function numberToByteString(number, options: numberToByteStringOptions = {}) {
    if (number < 0) {
      throw new Error('Number must be non-negative.');
    }
  
    const { endian = 'big', length = undefined } = options;
  
    // Calculate the number of bytes needed to represent the number
    const numBytes = Math.ceil(Math.log2(number + 1) / 8);
  
    // Create an array to store the bytes
    const bytes = new Array(numBytes);
  
    // Extract and store each byte
    for (let i = numBytes - 1; i >= 0; i--) {
      bytes[i] = number & 0xff; // Extract the least significant byte
      number >>= 8; // Shift right by 8 bits to get the next byte
    }
  
    // Convert the byte array to a ByteString
    const byteString = Buffer.from(bytes).toString('hex');
    let endianByteString = byteString; //endian === 'big' ? byteString : byteString.split('').reverse().join('');
    if(endian !== 'big'){
        endianByteString = '';
        for (let i = byteString.length; i > 0 ; i = i-2) {
            const byteHexString = byteString.slice(i-2,i);  
            // byteHexString = byteHexString.slice(1,2) + byteHexString.slice(0,1);   
            endianByteString = endianByteString + byteHexString;
        }
    }

    // Pad the ByteString with leading zeros if a specific length is requested
    if (length && length > numBytes * 2) {
      const padding = '0'.repeat(length - numBytes * 2);
      return endian === 'big' ? padding + endianByteString : endianByteString + padding;
    }
  
    return endianByteString;
  }

describe('Test SmartContract `RabinDemo`', () => {
    let instance: RabinDemo

    before(async () => {
        // GET https://witnessonchain.com/v1/info
/*         const response = await axios
            .get(`${witnessServer}/info`)
            .then((response) => response.data)
        // then parse Oracle's Rabin public key from the response
        const pubKey = RabinVerifierWOC.parsePubKey(response) */

        await RabinDemo.compile()
        // new contract instance
        instance = new RabinDemo()
        await instance.connect(getDefaultSigner())
    })

    // it('should pass the public method unit test successfully.', async () => {
    it('should pass the public method unit test successfully.', async function () {
        this.timeout(60000); // Set a longer timeout (in milliseconds)
        // GET https://witnessonchain.com/v1/rates/bsv_usdc
/*         const response = await axios
            .get(`${witnessServer}/rates/bsv_usdc`)
            .then((response) => response.data)
        // then parse Oracle's signed message and signature from the response
        const msg = RabinVerifierWOC.parseMsg(response)
        const sig = RabinVerifierWOC.parseSig(response) */

        const byteString = toByteString('258',true);
        console.log(`byteString: ${byteString}`); //byteString: 323538
        const byteString2 = BigInt(Buffer.from('323538', 'hex').toString('ascii'));
        console.log(`byteString2: ${byteString2}`); //byteString2: 258
        const byteString3 = BigInt(Buffer.from('258').toString('ascii'));
        console.log(`byteString3: ${byteString3}`); //byteString3: 258
        const byteString4 = toByteString('0201',true);
        console.log(`byteString4: ${byteString4}`); //byteString4: 30323031
        const leuint = Utils.fromLEUnsigned('02010000');
        console.log(`leuint: ${leuint}`); //leuint: 258
        const leuint2 = Utils.fromLEUnsigned('00000201');
        console.log(`leuint2: ${leuint2}`); //leuint2: 16908288
        const leuint3 = Utils.fromLEUnsigned('323538');
        console.log(`leuint3: ${leuint3}`); //leuint3: 3683634
        const leuint4 = Utils.fromLEUnsigned('0201');
        console.log(`leuint4: ${leuint4}`); //leuint4: 258
        const leuint5 = Utils.fromLEUnsigned('0102');
        console.log(`leuint5: ${leuint5}`); //leuint5: 513
        const leuint6 = Utils.fromLEUnsigned('20100000');
        console.log(`leuint6: ${leuint6}`); //leuint6: 4128

        const number = 258;
        const byteStringBuf = numberToByteString(number);
        console.log(`byteStringBuf: ${byteStringBuf}`);  // Output: "0102"

        const options = { endian: 'little', length: 8 }; // Little-endian and 8-character ByteString
        const byteStringBuf2 = numberToByteString(number, options);
        console.log(`byteStringBuf2: ${byteStringBuf2}`); // byteStringBuf2: 02010000

        /* const number = 258;
        // Create a Buffer with a single byte
        const buffer = Buffer.alloc(1);
        // Write the number as a 8-bit unsigned integer to the Buffer
        buffer.writeUInt8(number, 0);
        // Convert the Buffer to a ByteString
        const byteStringBuf = buffer.toString('hex');
        console.log(`byteStringBuf: ${byteStringBuf}`); // RangeError [ERR_OUT_OF_RANGE]: The value of "value" is out of range. It must be >= 0 and <= 255. Received 258
 */
        const digest = "30303030303033313136303030303139323139383030303030303031363933323632303430333034303030303030303136393332363230343033303431"
        const securityLevel = 6; //from 1(512bit) to 6(3072bit) or more
        const rabin = new Rabin(securityLevel);
        const issuerPrivateKey = bsv.PrivateKey.fromWIF("cUk71nvhD9YqsfD2FAAi4jc7kAQbxLUS3nNFNJfxW4i8tVVbtefW");
        const privateKey = rabin.generatePrivKeyFromSeed( issuerPrivateKey.toBuffer() );
        const publicKey = rabin.privKeyToPubKey(privateKey);
        console.log(`rabin.publicKey: ${publicKey}`);
        // rabin.publicKey: 806601590652956834018399678533433330297520166170621677718366777282597008261175369958720728325788781957301517421248979722124322014908005896229583387020751139752183740977977992209086123038969731450485318947788672763297547761693887724241199326085478474318421040040373573386924621067572175562203673198539124398617643535974063533030798711728926101490992140759381047314622647708525546076184615618641756952860677648413425031093445751156507332437310584683508880247430736178789021942005256459521793630277903367137027423426709231650428666408539139818974046833782009405081791441480798034660675416464075370612712674283657014595582339399258746911970999875576511830555755483835968845457351790361636021818838815015367880928091532562125760181215916964503709203093555467749323005045402306132828909170770279954434996949977916140155679733009945879625068160387460924966567486357375120600807460265701518792043161343124480625464663427359655993589
        const signature = rabin.sign(digest, privateKey);
        console.log(`rabin.signature.signature: ${signature.signature}`);
        // rabin.signature.signature: 590940996336715116405068293098281682144830614447477648747700106054773911064626297903814074376438294180224029937238764493382676637150645259190163649491995019424460118930168760021447314885488746416767525467035699982462891077312015748709317093476040391965110570676601896570094865581286581297292994910779236329228628398415954184782371666957995045238237712784899174699112192838353417093318153805519426299173388915972389129323662878887032735892393334823384547604980807807322971041988756731436417793115189517817414755777924457888607764637947504079592162335126803605919507360549563004422140552909328068664466495912205550410073073458789711967832629468834828193723765389343277532284502122735237204951217380925398098654382832797877842248617378792394554171459110032303314027047373210933267513995551666889231366211183719791678210724038411690626772685057055380183595502644866087288881000354040137214397205545914815239880446415201347385904
        console.log(`rabin.signature.paddingByteCount: ${signature.paddingByteCount}`);
        // rabin.signature.paddingByteCount: 1
        const verify = rabin.verify( digest, signature, publicKey );
        console.log(`rabin.verify: ${verify}`); 
        // rabin.verify: true

        const paddingByteString = Buffer.from('00'.repeat(signature.paddingByteCount), 'hex').toString('hex');
        console.log(`paddingByteString: ${paddingByteString}`); 
        const rabinSig: RabinSig = { s: signature.signature, padding: paddingByteString }

        // deploy the contract
        await instance.deploy()

        // call the contract and verify
        const call = async () => await instance.methods.unlock(digest, rabinSig)
        expect(call()).not.throw
    })
})
